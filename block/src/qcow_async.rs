use std::io::{Seek, SeekFrom};
use std::os::unix::io::{RawFd, AsRawFd};
use libc::iovec;
use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFile, DiskFileError, DiskFileResult};
use crate::qcow::{QcowFile, RawFile};
use crate::raw_async::RawFileAsync;
use crate::{BatchRequest, BlockBackend};

pub struct QcowDiskAsync(QcowFile);

impl QcowDiskAsync {
    pub fn new(file: std::fs::File) -> std::io::Result<Self> {
        let direct_io = false;
        let raw_file = RawFile::new(file, direct_io);
        let qcow_file = QcowFile::from(raw_file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e)))?;
        Ok(Self(qcow_file))
    }
}

impl DiskFile for QcowDiskAsync {
    fn size(&mut self) -> DiskFileResult<u64> {
        self.0.size().map_err(|e| {
            DiskFileError::Size(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{:?}", e),
            ))
        })
    }

    fn new_async_io(&self, ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(
            QcowAsync::new(self.0.clone(), ring_depth)
                .map_err(DiskFileError::NewAsyncIo)?,
        ) as Box<dyn AsyncIo>)
    }

    fn fd(&mut self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.0.as_raw_fd())
    }
}

pub struct QcowAsync {
    qcow: QcowFile,
    raw_file_async: RawFileAsync,
}

impl QcowAsync {
    pub fn new(qcow: QcowFile, ring_depth: u32) -> std::io::Result<Self> {
        let fd: RawFd = qcow.as_raw_fd();
        let raw_file_async = RawFileAsync::new(fd, ring_depth)?;
        Ok(QcowAsync {
            qcow,
            raw_file_async,
        })
    }
}

impl AsyncIo for QcowAsync {
    fn notifier(&self) -> &EventFd {
        self.raw_file_async.notifier()
    }

    fn read_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.raw_file_async.read_vectored(offset, iovecs, user_data)
    }

    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.raw_file_async.write_vectored(offset, iovecs, user_data)
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.raw_file_async.fsync(user_data)
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        self.raw_file_async.next_completed_request()
    }


    fn submit_batch_requests(&mut self, batch_request: &[BatchRequest]) -> AsyncIoResult<()> {
        // translate each BatchRequest guest offset(s) to host offsets and forward to RawFileAsync,
        // expanding requests when a single guest request maps to multiple host requests.
        self.raw_file_async.submit_batch_requests(batch_request)
    }
}