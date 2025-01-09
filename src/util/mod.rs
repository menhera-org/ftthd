
pub mod buffer;
pub mod kind;

use parking_lot::Mutex;

use std::sync::Arc;


#[derive(Debug)]
struct DropDetectorInner<F>
where 
    F: FnOnce(),
{
    on_drop: Option<F>,
}

impl<F> DropDetectorInner<F>
where
    F: FnOnce(),
{
    fn new(on_drop: F) -> Self {
        Self {
            on_drop: Some(on_drop),
        }
    }

    fn is_dropped(&self) -> bool {
        self.on_drop.is_none()
    }
}

impl<F> Drop for DropDetectorInner<F>
where 
    F: FnOnce(),
{
    fn drop(&mut self) {
        if let Some(on_drop) = self.on_drop.take() {
            on_drop();
        }
    }
}

pub struct DropDetector<F>
where 
    F: FnOnce(),
{
    id: u128,
    inner: Arc<Mutex<DropDetectorInner<F>>>,
}

impl<F> DropDetector<F>
where
    F: FnOnce(),
{
    pub fn new(on_drop: F) -> Self {
        Self {
            id: rand::random(),
            inner: Arc::new(Mutex::new(DropDetectorInner::new(on_drop))),
        }
    }

    pub fn is_dropped(&self) -> bool {
        self.inner.lock().is_dropped()
    }
}

impl<F> PartialEq for DropDetector<F>
where
    F: FnOnce(),
{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<F> Eq for DropDetector<F> where F: FnOnce() {}

impl<F> std::fmt::Debug for DropDetector<F>
where
    F: FnOnce(),
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "DropDetector({})", self.id)
    }
}

impl<F> Clone for DropDetector<F>
where
    F: FnOnce(),
{
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            inner: self.inner.clone(),
        }
    }
}

pub type BoxedDropDetector = DropDetector<Box<dyn FnOnce() + Send>>;

impl DropDetector<Box<dyn FnOnce() + Send>> {
    pub fn new_boxed(on_drop: impl FnOnce() + Send + 'static) -> Self {
        Self::new(Box::new(on_drop))
    }
}

