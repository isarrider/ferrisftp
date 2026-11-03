//! Constants from the SFTP version 3 specification
//! (draft-ietf-secsh-filexfer-02).

pub const SFTP_VERSION: u32 = 3;

/// Largest packet we accept or send, matching OpenSSH's sftp-server.
pub const MAX_PACKET_LEN: u32 = 256 * 1024;
/// Largest READ we serve in one response; leaves room for the DATA header.
pub const MAX_READ_LEN: u32 = 255 * 1024;
/// Upper bound on simultaneously open handles per session.
pub const MAX_HANDLES: usize = 512;
/// Entries returned per READDIR response.
pub const READDIR_BATCH: usize = 100;

// Packet types
pub const SSH_FXP_INIT: u8 = 1;
pub const SSH_FXP_VERSION: u8 = 2;
pub const SSH_FXP_OPEN: u8 = 3;
pub const SSH_FXP_CLOSE: u8 = 4;
pub const SSH_FXP_READ: u8 = 5;
pub const SSH_FXP_WRITE: u8 = 6;
pub const SSH_FXP_LSTAT: u8 = 7;
pub const SSH_FXP_FSTAT: u8 = 8;
pub const SSH_FXP_SETSTAT: u8 = 9;
pub const SSH_FXP_FSETSTAT: u8 = 10;
pub const SSH_FXP_OPENDIR: u8 = 11;
pub const SSH_FXP_READDIR: u8 = 12;
pub const SSH_FXP_REMOVE: u8 = 13;
pub const SSH_FXP_MKDIR: u8 = 14;
pub const SSH_FXP_RMDIR: u8 = 15;
pub const SSH_FXP_REALPATH: u8 = 16;
pub const SSH_FXP_STAT: u8 = 17;
pub const SSH_FXP_RENAME: u8 = 18;
pub const SSH_FXP_READLINK: u8 = 19;
pub const SSH_FXP_SYMLINK: u8 = 20;
pub const SSH_FXP_STATUS: u8 = 101;
pub const SSH_FXP_HANDLE: u8 = 102;
pub const SSH_FXP_DATA: u8 = 103;
pub const SSH_FXP_NAME: u8 = 104;
pub const SSH_FXP_ATTRS: u8 = 105;
pub const SSH_FXP_EXTENDED: u8 = 200;
pub const SSH_FXP_EXTENDED_REPLY: u8 = 201;

// Status codes
pub const SSH_FX_OK: u32 = 0;
pub const SSH_FX_EOF: u32 = 1;
pub const SSH_FX_NO_SUCH_FILE: u32 = 2;
pub const SSH_FX_PERMISSION_DENIED: u32 = 3;
pub const SSH_FX_FAILURE: u32 = 4;
pub const SSH_FX_BAD_MESSAGE: u32 = 5;
pub const SSH_FX_OP_UNSUPPORTED: u32 = 8;

// Open flags
pub const SSH_FXF_READ: u32 = 0x01;
pub const SSH_FXF_WRITE: u32 = 0x02;
pub const SSH_FXF_APPEND: u32 = 0x04;
pub const SSH_FXF_CREAT: u32 = 0x08;
pub const SSH_FXF_TRUNC: u32 = 0x10;
pub const SSH_FXF_EXCL: u32 = 0x20;

// Attribute flags
pub const SSH_FILEXFER_ATTR_SIZE: u32 = 0x01;
pub const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x02;
pub const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x04;
pub const SSH_FILEXFER_ATTR_ACMODTIME: u32 = 0x08;
pub const SSH_FILEXFER_ATTR_EXTENDED: u32 = 0x8000_0000;
