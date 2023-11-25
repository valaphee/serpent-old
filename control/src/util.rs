macro_rules! unique_id {
    () => {
        concat!(file!(), line!(), column!())
    };
}

pub(crate) use unique_id;
