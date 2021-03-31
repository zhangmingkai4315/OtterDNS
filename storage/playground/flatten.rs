pub trait IteratorExt: Iterator + Sized{
    fn flatten(self) -> Flatten<Self>
        where Self::Item: IntoIterator;
}

impl<T> IteratorExt for T where T: Iterator{
    fn flatten(self)-> Flatten<T>
        where Self::Item: IntoIterator
    {
        flatten(self)
    }
}

pub fn flatten<T>(iter: T) -> Flatten<T::IntoIter>
    where T: IntoIterator, T::Item: IntoIterator
{
    Flatten::new(iter.into_iter())
}

pub struct Flatten<T>
    where T: Iterator, T::Item: IntoIterator{
    outter: T,
    front_iter: Option<<T::Item as IntoIterator>::IntoIter>,
    back_iter: Option<<T::Item as IntoIterator>::IntoIter>
}

impl<T> Flatten<T>
    where T: Iterator, T::Item: IntoIterator{
    fn new(iter: T)->Self{
        Flatten{
            outter: iter,
            front_iter: None,
            back_iter: None,
        }
    }
}

impl<T> Iterator for Flatten<T>
    where T: Iterator, T::Item: IntoIterator{
    type Item = <T::Item as IntoIterator>::Item;
    fn next(&mut self)-> Option<Self::Item>{
        loop {
            if let Some(front_iter) = &mut self.front_iter{
                if let Some(i) = front_iter.next(){
                    return Some(i);
                }
                self.front_iter = None;
            }
            if let Some(next_inner) = self.outter.next(){
                self.front_iter = Some(next_inner.into_iter());
            }else{
                return self.back_iter.as_mut()?.next();
            }
        }
    }
}

impl<T> DoubleEndedIterator for Flatten<T>
    where T: DoubleEndedIterator, T::Item: IntoIterator, <T::Item as IntoIterator>::IntoIter: DoubleEndedIterator{
    fn next_back(&mut self) -> Option<Self::Item>{
        loop {
            if let Some(back_item) = &mut self.back_iter{
                if let Some(i) = back_item.next_back(){
                    return Some(i);
                }
                self.back_iter = None;
            }
            if let Some(next_back_inner) = self.outter.next_back(){
                self.back_iter = Some(next_back_inner.into_iter());
            }else{
                return self.front_iter.as_mut()?.next_back();
            }

        }
    }
}

#[cfg(test)]
mod test{
    use super::*;
    #[test]
    fn test_iteraor(){
        let a = vec![vec![1,1,1,1],vec![2,2,2,2], vec![3,3,3,3]];
        let b = flatten(a);
        for x in b {
            println!("{}", x)
        }
        let a = vec![vec![1,1,1,1],vec![2,2,2,2], vec![3,3,3,3]];
        let b = flatten(a).rev();
        for x in b {
            println!("{}", x)
        }
    }
}