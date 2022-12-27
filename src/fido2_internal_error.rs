#[derive(Debug)]
pub(crate) enum FIDO2InternalError {
    ReversedChannelError,
    DataLengthError,
    CommandNotFoundError,
}
