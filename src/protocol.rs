//! Version 1 wire types. These `derive(Message)` definitions are the canonical wire schema.
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use prost::Message;

use crate::{Error, Result};

pub const DIRECTORY_PROTOCOL: &str = "/jlucraft/union/directory/1";
pub const SESSION_PROTOCOL: &str = "/jlucraft/union/session/1";
pub const MAX_FRAME: usize = 64 * 1024;
pub const MAX_SERVICES: usize = 64;

#[derive(Clone, PartialEq, Message)]
pub struct DirectoryRequest {}

#[derive(Clone, PartialEq, Message)]
pub struct ServiceRecord {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub protocol: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct DirectoryResponse {
    #[prost(message, repeated, tag = "1")]
    pub services: Vec<ServiceRecord>,
}

#[derive(Clone, PartialEq, Message)]
pub struct OpenRequest {
    #[prost(string, tag = "1")]
    pub service_id: String,
    #[prost(message, optional, tag = "2")]
    pub grant: Option<GrantEnvelope>,
    #[prost(bytes = "vec", tag = "3")]
    pub student: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct OpenResponse {
    #[prost(enumeration = "Status", tag = "1")]
    pub status: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum Status {
    Unspecified = 0,
    Accepted = 1,
    Denied = 2,
    NotFound = 3,
    Busy = 4,
}

#[derive(Clone, PartialEq, Message)]
pub struct GrantClaims {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(bytes = "vec", tag = "2")]
    pub subject: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub audience: Vec<u8>,
    #[prost(string, tag = "4")]
    pub service_id: String,
    #[prost(uint64, tag = "5")]
    pub not_before: u64,
    #[prost(uint64, tag = "6")]
    pub expires_at: u64,
}

#[derive(Clone, PartialEq, Message)]
pub struct GrantEnvelope {
    #[prost(bytes = "vec", tag = "1")]
    pub claims: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub issuer_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub signature: Vec<u8>,
}

/// A four-byte big-endian size followed by protobuf; bounded before allocation.
pub async fn read_frame<M: Message + Default>(reader: &mut (impl AsyncRead + Unpin)) -> Result<M> {
    let mut size = [0; 4];
    reader.read_exact(&mut size).await?;
    let size = u32::from_be_bytes(size) as usize;
    if size > MAX_FRAME {
        return Err(Error::Protocol("frame too large".into()));
    }
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes).await?;
    M::decode(bytes.as_slice()).map_err(|e| Error::Protocol(e.to_string()))
}

pub async fn write_frame<M: Message>(
    writer: &mut (impl AsyncWrite + Unpin),
    message: &M,
) -> Result<()> {
    let size = message.encoded_len();
    if size > MAX_FRAME {
        return Err(Error::Protocol("frame too large".into()));
    }
    writer.write_all(&(size as u32).to_be_bytes()).await?;
    writer.write_all(&message.encode_to_vec()).await?;
    writer.flush().await?;
    Ok(())
}
