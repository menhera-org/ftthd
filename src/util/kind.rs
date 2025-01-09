
use std::marker::PhantomData;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum _Nothing {}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KindTag<const UUID: u128> {
    _never: _Nothing,
}

trait _IsKindTag {}

impl<const UUID: u128> _IsKindTag for KindTag<UUID> {}

#[allow(private_bounds)]
pub trait KindTagImpl
where 
    Self: _IsKindTag,
{
    type Item: Sized;
    const NAME: &'static str;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NoKindTag<T>
where 
    T: Sized,
{
    _never: _Nothing,
    _phantom: PhantomData<T>,
}

pub trait Kind {
    type Item: Sized;

    /// Should be const, but it's not supported yet
    fn name() -> &'static str;
}

impl<T> Kind for NoKindTag<T>
where 
    T: Sized,
{
    type Item = T;

    fn name() -> &'static str {
        std::any::type_name::<T>()
    }
}

impl<T> Kind for T
where 
    T: KindTagImpl,
{
    type Item = T::Item;

    fn name() -> &'static str {
        T::NAME
    }
}
