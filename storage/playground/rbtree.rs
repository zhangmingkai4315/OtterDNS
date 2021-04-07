use std::cell::RefCell;
use std::ops::Deref;
use std::rc::Rc;

// assume this is a red-black tree
#[derive(Debug)]
struct RBTree(Vec<(String, Node)>);

impl RBTree {
    fn search(&self, key: String) -> Option<Node> {
        for (k, v) in self.0.iter() {
            if key.eq(k) {
                return Some((*v).clone());
            }
        }
        None
    }
    // if this is a path node, Option Value is None
    fn insert_node(&mut self, key: String, value: Option<usize>) -> Rc<RefCell<RBTree>> {
        let rc = Rc::from(RefCell::from(RBTree(vec![])));
        self.0.push((
            key.clone(),
            Node {
                label: key,
                data: value.unwrap_or(0),
                subtree: rc.clone(),
            },
        ));
        rc
    }
}

// each node have a rbtree
#[derive(Clone, Debug)]
struct Node {
    label: String,
    data: usize,
    subtree: Rc<RefCell<RBTree>>,
}
#[derive(Clone, Debug)]
struct Storage {
    root: Node,
}

impl Storage {
    fn new() -> Storage {
        Storage {
            root: Node {
                label: "".to_string(),
                data: 0,
                subtree: Rc::from(RefCell::from(RBTree(vec![]))),
            },
        }
    }
    fn insert(&mut self, labels: Vec<String>, value: usize) {
        let mut root = self.root.subtree.clone();
        let mut labels_count = labels.len();
        for i in labels {
            labels_count -= 1;
            let subtree_borrow = root.deref().borrow();
            //Compile Error: `subtree_borrow` does not live long enough
            let result = subtree_borrow.search(i.clone());
            drop(subtree_borrow);
            match result {
                Some(v) => root = v.subtree.clone(),
                _ => {
                    if labels_count == 0 {
                        root.borrow_mut().insert_node(i, Some(value));
                        return;
                    }
                    let subtree = root.borrow_mut().insert_node(i, None);
                    root = subtree.clone();
                    // root.borrow
                    // move next level
                }
            }
        }
    }
}

fn main() {
    let mut storage = Storage::new();
    storage.insert(vec!["1".to_owned(), "2".to_owned(), "3".to_owned()], 10);
    storage.insert(vec!["1".to_owned(), "2".to_owned(), "4".to_owned()], 20);
    storage.insert(vec!["1".to_owned(), "1".to_owned()], 30);
}
