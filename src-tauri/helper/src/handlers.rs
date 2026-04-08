use crate::protocol::{Request, Response};

pub fn handle(_request: Request) -> Response {
    Response::error("not implemented".to_string())
}
