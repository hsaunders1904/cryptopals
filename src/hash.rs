pub trait Hasher<const N: usize>: Default {
    fn update(&mut self, data: &[u8]);

    fn digest(self) -> [u8; N];

    fn digest_message(message: &[u8]) -> [u8; N] {
        let mut hasher = Self::default();
        hasher.update(message);
        hasher.digest()
    }

    fn update_and_digest(mut self, message: &[u8]) -> [u8; N] {
        self.update(message);
        self.digest()
    }
}
