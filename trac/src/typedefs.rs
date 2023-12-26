pub trait Resource {
    fn trace_start(&mut self);
    fn to_csv_lines(&mut self) -> Vec<String>;
}
