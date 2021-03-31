use std::{cell::{UnsafeCell}, marker::PhantomData, ops::Deref, ptr::NonNull, usize};
#[derive(Debug)]
struct Cell<T>{
    value: UnsafeCell<T>,
}

unsafe impl<T> Sync for Cell<T> {}
unsafe impl<T> Send for Cell<T> {}

impl<T> Cell<T>{
    pub fn new(value: T) -> Self{
        Cell{
            value: UnsafeCell::new(value),
        }
    }

    pub fn set(&self, value: T){
        unsafe {
            *self.value.get() = value;
        }
    }

    pub fn get(&self)->T where T: Copy {
        unsafe {
            *self.value.get()
        }
    }
}

#[test]
fn concurrent_set(){
    use std::sync::Arc;
    use super::cell;
    let x= Arc::new(cell::Cell::new(42));
    let x1 = Arc::clone(&x);
    let a = std::thread::spawn(move || {
        x1.set(10);
    });
    let x2 = Arc::clone(&x);
    let b = std::thread::spawn(move||{
        x2.set(20);
    });

    a.join().unwrap();
    b.join().unwrap();
    eprint!("{:?}", x.get());
    //20
}

#[test]
fn concurrent_set_array(){
    use std::sync::Arc;
    use super::cell;
    let x= Arc::new(cell::Cell::new(0));
    let x1 = Arc::clone(&x);
    let a = std::thread::spawn(move || {
        for _ in 0..=10000{
            x1.set(x1.get()+1);
        }
    });
    let x2 = Arc::clone(&x);
    let b = std::thread::spawn(move||{
        for _ in 0..=10000{
            x2.set(x2.get()+1);
        }
    });

    a.join().unwrap();
    b.join().unwrap();
    eprint!("{:?}", x.get());
    //10785
}

struct RcInner<T>{
    value: T,
    refcount: Cell<usize>
}
impl<T> RcInner<T> {
    fn get_counter(&self)->usize{
        self.refcount.get()
    }
}

struct Rc<T>{
    inner: NonNull<RcInner<T>>,
    _marker: PhantomData<RcInner<T>>
}

impl<T> Rc<T> {
    pub fn new(v: T) -> Self{
        let inner = Box::new(RcInner{
            value: v,
            refcount: Cell::new(1),
        });

        Rc{
            inner: unsafe{ NonNull::new_unchecked(Box::into_raw(inner))},
            _marker: PhantomData,
        }
    }
    pub fn get_counter(&self)->usize{
        unsafe {
            self.inner.as_ref()
        }.get_counter()
    }
}

impl<T> std::ops::Deref for Rc<T>{
    type Target = T;
    fn deref(&self) -> &Self::Target{
        & unsafe {
            self.inner.as_ref()
        }.value
    }
}

impl<T> Clone for Rc<T>{
    fn clone(&self) -> Self{
        let inner = unsafe {
            self.inner.as_ref()
        };
        let c = inner.refcount.get();
        inner.refcount.set(c + 1);
        Rc{
            inner: self.inner,
            _marker: PhantomData,
        }
    }
}

impl<T> Drop for Rc<T>{
    fn drop(&mut self){
        let inner = unsafe {
            self.inner.as_ref()
        };
        let c= &inner.refcount.get();
        if *c==1{
            drop(inner);
            let _ = unsafe { Box::from_raw(self.inner.as_ptr())};
        }else{
            inner.refcount.set(c-1);
        }
    }
}

#[test]
fn test_rc(){
    use super::*;
    let a = Rc::new(Box::new(43));
    let b = a.clone();
    eprint!("{}\n", a.get_counter());
    drop(b);
    eprint!("{}\n", a.get_counter());
    // 2
    // 1
}

#[derive(Debug,Clone,Copy)]
enum RefState{
    Unshared,
    Shared(usize),
    Exclusive,
}
struct RefCell<T>{
    value: UnsafeCell<T>,
    state: Cell<RefState>,
}

pub struct Ref<'refcell, T>{
    refcell: &'refcell RefCell<T>,
}
impl<T> Deref for Ref<'_, T> {
    type Target = T;
    fn deref(&self)->&Self::Target{
        unsafe {
            &*self.refcell.value.get()
        }
    }
}

impl<T> Drop for Ref<'_, T> {
    fn drop(&mut self){
        match &self.refcell.state.get() {
            RefState::Exclusive | RefState::Unshared => {unreachable!()},
            RefState::Shared(1) => {
                self.refcell.state.set(RefState::Unshared);
            }
            RefState::Shared(n) => {
                self.refcell.state.set(RefState::Shared(n-1));
            }
        }
    }
}
pub struct RefMut<'refcell, T> {
    refcell: &'refcell RefCell<T>,
}

impl<T> std::ops::Deref for RefMut<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.refcell.value.get() }
    }
}

impl<T> std::ops::DerefMut for RefMut<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.refcell.value.get() }
    }
}

impl<T> Drop for RefMut<'_, T>{
    fn drop(&mut self){
        match self.refcell.state.get() {
            RefState::Unshared | RefState::Shared(_) => unreachable!(),
            RefState::Exclusive => self.refcell.state.set(RefState::Unshared)
        }
    }
}

impl<T> RefCell<T> {
    fn new(value: T)->Self{
        Self{
            value: UnsafeCell::new(value),
            state: Cell::new(RefState::Unshared)
        }
    }

    pub fn borrow(&self)-> Option<Ref<'_, T>>{
        match self.state.get() {
            RefState::Unshared => {
                self.state.set(RefState::Shared(1));
                Some(Ref{ refcell: self })
            },
            RefState::Shared(n) => {
                self.state.set(RefState::Shared(n+1));
                Some(Ref{ refcell: self })
            },
            RefState::Exclusive => None,
        }
    }

    pub fn borrow_mut(&self)-> Option<RefMut<'_, T>>{
        if let RefState::Unshared = self.state.get(){
            self.state.set(RefState::Exclusive);
            Some(RefMut {refcell: self})
        }else {
            None
        }
    }
}
