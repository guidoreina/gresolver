#ifndef RED_BLACK_TREE_H
#define RED_BLACK_TREE_H

#define MAX_ERASED_NODES 1024

template<typename T>
class red_black_tree {
	private:
		struct node {
			T data;

			unsigned char color;

			struct node* p;
			struct node* left;
			struct node* right;
		};

	public:
		struct iterator {
			friend class red_black_tree;

			public:
				T* data;

			private:
				struct node* node;
		};

		// Constructor.
		red_black_tree();

		// Destructor.
		virtual ~red_black_tree();

		// Set destroy callback.
		void set_destroy_callback(void (*destroy)(T*));

		// Clear.
		void clear();

		// Get the number of elements.
		size_t size() const;

		// true if the red-black-tree's size is 0.
		bool empty() const;

		// Insert.
		bool insert(const T& data, iterator* it = NULL);

		// Erase.
		void erase(iterator& it);
		bool erase(const T& data);

		// Find.
		bool find(const T& data, iterator& it);

		// Begin.
		bool begin(iterator& it);

		// End.
		bool end(iterator& it);

		// Next.
		bool next(iterator& it);

		// Previous.
		bool previous(iterator& it);

	private:
		static const unsigned char RED;
		static const unsigned char BLACK;

		node _M_nil;

		node* _M_root;
		size_t _M_used;

		node* _M_erased[MAX_ERASED_NODES];
		size_t _M_nerased;

		void (*_M_destroy)(T*);

		// Search node.
		node* search(const T& data);

		// Transplant.
		void transplant(node* u, node* v);

		// Left rotate.
		void left_rotate(node* x);

		// Right rotate.
		void right_rotate(node* y);

		// Insert fixup.
		void insert_fixup(node* z);

		// Delete fixup.
		void delete_fixup(node* x);

		// Minimum.
		node* minimum(node* x);

		// Maximum.
		node* maximum(node* x);

		// Successor.
		node* successor(node* x);

		// Predecessor.
		node* predecessor(node* x);

		// Erase.
		void erase(node* x);
};

#define _nil (&_M_nil)

template<typename T>
const unsigned char red_black_tree<T>::RED = 0;

template<typename T>
const unsigned char red_black_tree<T>::BLACK = 1;

template<typename T>
red_black_tree<T>::red_black_tree()
{
	_M_nil.color = BLACK;

	_M_root = _nil;
	_M_used = 0;

	_M_nerased = 0;

	_M_destroy = NULL;
}

template<typename T>
inline red_black_tree<T>::~red_black_tree()
{
	clear();
}

template<typename T>
inline void red_black_tree<T>::set_destroy_callback(void (*destroy)(T*))
{
	_M_destroy = destroy;
}

template<typename T>
void red_black_tree<T>::clear()
{
	if (_M_root != _nil) {
		erase(_M_root);
		_M_root = _nil;

		_M_used = 0;
	}

	for (size_t i = 0; i < _M_nerased; i++) {
		free(_M_erased[i]);
	}

	_M_nerased = 0;
}

template<typename T>
inline size_t red_black_tree<T>::size() const
{
	return _M_used;
}

template<typename T>
inline bool red_black_tree<T>::empty() const
{
	return (_M_used == 0);
}

template<typename T>
bool red_black_tree<T>::insert(const T& data, iterator* it)
{
	node* z;
	if (_M_nerased > 0) {
		z = _M_erased[--_M_nerased];
	} else {
		if ((z = (struct node*) malloc(sizeof(struct node))) == NULL) {
			return false;
		}
	}

	z->data = data;

	node* y = _nil;
	node* x = _M_root;

	while (x != _nil) {
		y = x;
		if (z->data < x->data) {
			x = x->left;
		} else {
			x = x->right;
		}
	}

	z->p = y;
	if (y == _nil) {
		_M_root = z;
	} else if (z->data < y->data) {
		y->left = z;
	} else {
		y->right = z;
	}

	z->left = _nil;
	z->right = _nil;
	z->color = RED;

	insert_fixup(z);

	_M_used++;

	if (it) {
		it->node = z;
		it->data = &z->data;
	}

	return true;
}

template<typename T>
void red_black_tree<T>::erase(iterator& it)
{
	node* z = it.node;

	node* x;
	node* y = z;
	unsigned char ycolor = y->color;

	if (z->left == _nil) {
		x = z->right;
		transplant(z, z->right);
	} else if (z->right == _nil) {
		x = z->left;
		transplant(z, z->left);
	} else {
		y = minimum(z->right);
		ycolor = y->color;
		x = y->right;

		if (y->p == z) {
			x->p = y;
		} else {
			transplant(y, y->right);
			y->right = z->right;
			y->right->p = y;
		}

		transplant(z, y);
		y->left = z->left;
		y->left->p = y;
		y->color = z->color;
	}

	if (ycolor == BLACK) {
		delete_fixup(x);
	}

	if (_M_destroy) {
		_M_destroy(&z->data);
	}

	if (_M_nerased == MAX_ERASED_NODES) {
		free(z);
	} else {
		_M_erased[_M_nerased++] = z;
	}

	_M_used--;
}

template<typename T>
bool red_black_tree<T>::erase(const T& data)
{
	iterator it;
	if ((it.node = search(data)) == _nil) {
		// Not found.
		return false;
	}

	erase(it);

	return true;
}

template<typename T>
bool red_black_tree<T>::find(const T& data, iterator& it)
{
	if ((it.node = search(data)) == _nil) {
		// Not found.
		return false;
	}

	it.data = &it.node->data;

	return true;
}

template<typename T>
bool red_black_tree<T>::begin(iterator& it)
{
	if (_M_root == _nil) {
		return false;
	}

	it.node = minimum(_M_root);
	it.data = &it.node->data;

	return true;
}

template<typename T>
bool red_black_tree<T>::end(iterator& it)
{
	if (_M_root == _nil) {
		return false;
	}

	it.node = maximum(_M_root);
	it.data = &it.node->data;

	return true;
}

template<typename T>
bool red_black_tree<T>::next(iterator& it)
{
	if ((it.node = successor(it.node)) == _nil) {
		return false;
	}

	it.data = &it.node->data;

	return true;
}

template<typename T>
bool red_black_tree<T>::previous(iterator& it)
{
	if ((it.node = predecessor(it.node)) == _nil) {
		return false;
	}

	it.data = &it.node->data;

	return true;
}

template<typename T>
struct red_black_tree<T>::node* red_black_tree<T>::search(const T& data)
{
	node* node = _M_root;
	while (node != _nil) {
		int ret = data - node->data;
		if (ret < 0) {
			node = node->left;
		} else if (ret == 0) {
			return node;
		} else {
			node = node->right;
		}
	}

	return _nil;
}

template<typename T>
void red_black_tree<T>::transplant(node* u, node* v)
{
	if (u->p == _nil) {
		_M_root = v;
	} else if (u == u->p->left) {
		u->p->left = v;
	} else {
		u->p->right = v;
	}

	v->p = u->p;
}

template<typename T>
void red_black_tree<T>::left_rotate(node* x)
{
	node* y = x->right;
	x->right = y->left;

	if (y->left != _nil) {
		y->left->p = x;
	}

	y->p = x->p;

	// Sentinel?
	if (x->p == _nil) {
		_M_root = y;
	} else if (x == x->p->left) {
		x->p->left = y;
	} else {
		x->p->right = y;
	}

	y->left = x;
	x->p = y;
}

template<typename T>
void red_black_tree<T>::right_rotate(node* y)
{
	node* x = y->left;
	y->left = x->right;

	if (x->right != _nil) {
		x->right->p = y;
	}

	x->p = y->p;

	// Sentinel?
	if (y->p == _nil) {
		_M_root = x;
	} else if (y == y->p->right) {
		y->p->right = x;
	} else {
		y->p->left = x;
	}

	x->right = y;
	y->p = x;
}

template<typename T>
void red_black_tree<T>::insert_fixup(node* z)
{
	while (z->p->color == RED) {
		if (z->p == z->p->p->left) {
			node* y = z->p->p->right;
			if (y->color == RED) {
				z->p->color = BLACK;
				y->color = BLACK;
				z->p->p->color = RED;

				z = z->p->p;
			} else {
				if (z == z->p->right) {
					z = z->p;
					left_rotate(z);
				}

				z->p->color = BLACK;
				z->p->p->color = RED;

				right_rotate(z->p->p);
			}
		} else {
			node* y = z->p->p->left;
			if (y->color == RED) {
				z->p->color = BLACK;
				y->color = BLACK;
				z->p->p->color = RED;

				z = z->p->p;
			} else {
				if (z == z->p->left) {
					z = z->p;
					right_rotate(z);
				}

				z->p->color = BLACK;
				z->p->p->color = RED;

				left_rotate(z->p->p);
			}
		}
	}

	_M_root->color = BLACK;
}

template<typename T>
void red_black_tree<T>::delete_fixup(node* x)
{
	while ((x != _M_root) && (x->color == BLACK)) {
		if (x == x->p->left) {
			node* w = x->p->right;
			if (w->color == RED) {
				w->color = BLACK;
				x->p->color = RED;

				left_rotate(x->p);
				w = x->p->right;
			}

			if ((w->left->color == BLACK) && (w->right->color == BLACK)) {
				w->color = RED;
				x = x->p;
			} else {
				if (w->right->color == BLACK) {
					w->left->color = BLACK;
					w->color = RED;

					right_rotate(w);
					w = x->p->right;
				}

				w->color = x->p->color;
				x->p->color = BLACK;
				w->right->color = BLACK;

				left_rotate(x->p);
				x = _M_root;
			}
		} else {
			node* w = x->p->left;
			if (w->color == RED) {
				w->color = BLACK;
				x->p->color = RED;

				right_rotate(x->p);
				w = x->p->left;
			}

			if ((w->right->color == BLACK) && (w->left->color == BLACK)) {
				w->color = RED;
				x = x->p;
			} else {
				if (w->left->color == BLACK) {
					w->right->color = BLACK;
					w->color = RED;

					left_rotate(w);
					w = x->p->left;
				}

				w->color = x->p->color;
				x->p->color = BLACK;
				w->left->color = BLACK;

				right_rotate(x->p);
				x = _M_root;
			}
		}
	}

	x->color = BLACK;
}

template<typename T>
inline struct red_black_tree<T>::node* red_black_tree<T>::minimum(node* x)
{
	while (x->left != _nil) {
		x = x->left;
	}

	return x;
}

template<typename T>
inline struct red_black_tree<T>::node* red_black_tree<T>::maximum(node* x)
{
	while (x->right != _nil) {
		x = x->right;
	}

	return x;
}

template<typename T>
struct red_black_tree<T>::node* red_black_tree<T>::successor(node* x)
{
	if (x->right != _nil) {
		return minimum(x->right);
	}

	node* y = x->p;
	while ((y != _nil) && (x == y->right)) {
		x = y;
		y = y->p;
	}

	return y;
}

template<typename T>
struct red_black_tree<T>::node* red_black_tree<T>::predecessor(node* x)
{
	if (x->left != _nil) {
		return maximum(x->left);
	}

	node* y = x->p;
	while ((y != _nil) && (x == y->left)) {
		x = y;
		y = y->p;
	}

	return y;
}

template<typename T>
void red_black_tree<T>::erase(node* x)
{
	if (x->left != _nil) {
		erase(x->left);
	}

	if (x->right != _nil) {
		erase(x->right);
	}

	if (_M_destroy) {
		_M_destroy(&x->data);
	}

	free(x);
}

#endif // RED_BLACK_TREE_H
