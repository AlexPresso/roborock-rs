struct RequestPayload<T> {
    id: i32,
    method: String,
    params: Option<T>,
}

struct ResponsePayload<T> {
    id: i32,
    result: T,
    exe_time: Option<u32>
}
