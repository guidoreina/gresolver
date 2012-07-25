#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include "resolver.h"

const unsigned short resolver::DNS_SERVER_PORT = 53;
const size_t resolver::LABEL_MAX_LEN = 63;
const unsigned resolver::MAX_RECURSION = 32;
const unsigned resolver::MAX_COMPRESSION_POINTERS = NAME_MAX_LEN;
const unsigned resolver::TTL_NO_DOMAIN = 10 * 60;

resolver::resolver()
{
	_M_id = 0;

	_M_cache.set_destroy_callback(resolver::dns_entry::destroy);
}

resolver::~resolver()
{
}

bool resolver::resolve(const char* name, size_t namelen, rr_type type)
{
	if ((namelen == 0) || (namelen >= NAME_MAX_LEN)) {
		return false;
	}

	// Check if the name is in the cache.
	dns_entry* e;
	dns_entry entry;
	entry.name = const_cast<char*>(name);
	entry.namelen = namelen;
	red_black_tree<dns_entry>::iterator it;
	if (_M_cache.find(entry, it)) {
#if DEBUG
		printf("[resolver::resolve] Name [%.*s] found in the cache.\n", namelen, name);
#endif

		time_t now = time(NULL);

		e = it.data;
		const struct address* address;
		unsigned short naddresses;

		switch (e->type) {
			case (unsigned short) STATUS_WAITING:
				return true;
			case (unsigned short) STATUS_NO_DOMAIN:
				if (now < e->timestamp + (time_t) TTL_NO_DOMAIN) {
					return false;
				}

				break;
			default: // STATUS_VALID.
				address = e->addresses;
				naddresses = e->naddresses;

				for (unsigned short i = 0; i < naddresses; i++, address++) {
					if (now < address->expire) {
						return true;
					}
				}
		}

#if DEBUG
		printf("[resolver::resolve] Have to resolve [%.*s] again.\n", namelen, name);
#endif

		e->destroy_addresses();
	} else {
		e = NULL;
	}

	return make_request(name, namelen, type, e != NULL);
}

bool resolver::make_request(const char* name, size_t namelen, rr_type type, bool in_cache)
{
	msg msg;
	msg.h = (header*) msg.data;

	fill_header(msg.h, QUERY_STANDARD);

	size_t size;
	if (!fill_question(name, namelen, type, msg.data + sizeof(header), size)) {
		return false;
	}

	size += sizeof(header);

	if (!in_cache) {
		if (!add_to_cache(name, namelen, type)) {
			return false;
		}
	}

	int sd;
	if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		return false;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = 0x0102a8c0;
	addr.sin_port = htons(DNS_SERVER_PORT);

	memset(&addr.sin_zero, 0, sizeof(addr.sin_zero));

	ssize_t ret;
	if ((ret = sendto(sd, msg.data, size, 0, (const struct sockaddr*) &addr, sizeof(struct sockaddr))) != (ssize_t) size) {
		perror("sendto");
		close(sd);
		return false;
	}

	socklen_t addrlen = sizeof(struct sockaddr);
	if ((ret = recvfrom(sd, msg.data, sizeof(msg.data), 0, (struct sockaddr*) &addr, &addrlen)) < 0) {
		perror("sendto");
		close(sd);
		return false;
	}

	close(sd);

	msg.end = msg.data + ret;

	return parse_message(msg);
}

bool resolver::add_to_cache(const char* name, size_t namelen, rr_type type, red_black_tree<dns_entry>::iterator* it)
{
#if DEBUG
	printf("[resolver::add_to_cache] Registering entry [%.*s] in the cache.\n", namelen, name);
#endif

	dns_entry entry;
	if (!entry.init(name, namelen, type, time(NULL))) {
		return false;
	}

	// Insert DNS entry in the cache.
	if (!_M_cache.insert(entry, it)) {
		free(entry.name);
		return false;
	}

	return true;
}

bool resolver::fill_question(const char* name, size_t namelen, rr_type type, unsigned char* buf, size_t& size)
{
	const char* ptr = name;
	const char* end = name + namelen;

	size_t l = 1; // Zero length octect for the null label of the root.
	size_t labellen = 0;

	int state = 0;

	while (ptr < end) {
		unsigned char c = (unsigned char) *ptr++;

		switch (state) {
			case 0:
				if ((l += 2) > NAME_MAX_LEN) {
					return false;
				}

				if (!IS_ALPHA(c)) {
					return false;
				}

				buf++; // Skip length octect.
				*buf++ = c;

				labellen = 1;

				state = 1;

				break;
			case 1:
				if (c == '.') {
					buf[-(1 + labellen)] = (unsigned char) labellen;

					state = 0;
				} else if ((IS_ALPHA(c)) || (IS_DIGIT(c))) {
					if (++l > NAME_MAX_LEN) {
						return false;
					}

					if (++labellen > LABEL_MAX_LEN) {
						return false;
					}

					*buf++ = c;
				} else if (c == '-') {
					if (++l > NAME_MAX_LEN) {
						return false;
					}

					if (++labellen > LABEL_MAX_LEN) {
						return false;
					}

					*buf++ = c;

					state = 2;
				} else {
					return false;
				}

				break;
			case 2:
				if ((IS_ALPHA(c)) || (IS_DIGIT(c))) {
					if (++l > NAME_MAX_LEN) {
						return false;
					}

					if (++labellen > LABEL_MAX_LEN) {
						return false;
					}

					*buf++ = c;

					state = 1;
				} else {
					return false;
				}

				break;
		}
	}

	if (state != 1) {
		return false;
	}

	buf[-(1 + labellen)] = (unsigned char) labellen;

	*buf++ = 0; // Zero length octect for the null label of the root.

	// QTYPE.
	*buf++ = (unsigned char) ((type >> 8) & 0xff);
	*buf++ = (unsigned char) (type & 0xff);

	// CLASS.
	*buf++ = 0;
	*buf = 1; // IN (Internet).

	size = l + 4;

	return true;
}

bool resolver::parse_message(msg& msg)
{
	if ((size_t) (msg.end - msg.data) <= sizeof(header)) {
		return false;
	}

	if (!parse_header(msg)) {
		return false;
	}

	if (msg.h->ancount == 0) {
		return false;
	}

	if (!find_first_record(msg)) {
		return false;
	}

	dns_entry entry;
	entry.name = msg.name;
	entry.namelen = msg.namelen;

	red_black_tree<dns_entry>::iterator it;
	if (!_M_cache.find(entry, it)) {
		// Name not found in the cache.
		return false;
	}

	dns_entry* e = it.data;

	msg.narecords = 0;
	msg.cnamelen = 0;

	for (unsigned short i = msg.h->ancount; (msg.ptr < msg.end) && (i > 0); i--) {
		rr rr;
		if (!find_next_record(msg, rr)) {
			return false;
		}

		if (!process_record(msg, rr)) {
			return false;
		}
	}

	time_t now = time(NULL);

	if (msg.narecords == 1) {
		// If not the original request...
		if (e->cnamelen > 0) {
			// The domain name of the original request is in e->cname.
			red_black_tree<dns_entry>::iterator itcname;
			if (!find(e->cname, e->cnamelen, itcname)) {
				_M_cache.erase(it);
				return false;
			}

			_M_cache.erase(it);

			e = itcname.data;
		}

		struct address* addr = msg.arecords;

		e->address.addr = addr->addr;
		e->address.expire = now + addr->expire;
		e->address.preference = addr->preference;

		e->addresses = &e->address;
		e->naddresses = 1;

		e->status = STATUS_VALID;

		return true;
	} else if (msg.narecords > 1) {
		// If not the original request...
		if (e->cnamelen > 0) {
			// The domain name of the original request is in e->cname.
			red_black_tree<dns_entry>::iterator itcname;
			if (!find(e->cname, e->cnamelen, itcname)) {
				_M_cache.erase(it);
				return false;
			}

			_M_cache.erase(it);

			e = itcname.data;
		}

		if ((e->addresses = (struct address*) malloc(msg.narecords * sizeof(struct address))) == NULL) {
			_M_cache.erase(it);
			return false;
		}

		struct address* addr = msg.arecords;
		for (unsigned short i = 0; i < msg.narecords; i++, addr++) {
			e->addresses[i].addr = addr->addr;
			e->addresses[i].expire = now + addr->expire;
			e->addresses[i].preference = addr->preference;
		}

		e->naddresses = msg.narecords;

		e->status = STATUS_VALID;

		return true;
	} else if (msg.cnamelen > 0) {
		dns_entry* ecname;

		// If not the original request...
		if (e->cnamelen > 0) {
			// The domain name of the original request is in e->cname.
			char* cname = e->cname;
			unsigned short cnamelen = e->cnamelen;

			red_black_tree<dns_entry>::iterator itcname;
			if (!find(cname, cnamelen, itcname)) {
				_M_cache.erase(it);
				return false;
			}

			e->cnamelen = 0;

			_M_cache.erase(it);

			if (++itcname.data->recursion > MAX_RECURSION) {
				_M_cache.erase(itcname);
				free(cname);
				return false;
			}

			if (!add_to_cache(msg.cname, msg.cnamelen, (rr_type) msg.type, &itcname)) {
				_M_cache.erase(itcname);
				free(cname);
				return false;
			}

			ecname = itcname.data;
			ecname->cname = cname;
			ecname->cnamelen = cnamelen;
		} else {
			red_black_tree<dns_entry>::iterator itcname;
			if (!add_to_cache(msg.cname, msg.cnamelen, (rr_type) msg.type, &itcname)) {
				_M_cache.erase(it);
				return false;
			}

			ecname = itcname.data;
			if ((ecname->cname = (char*) malloc(msg.namelen)) == NULL) {
				_M_cache.erase(itcname);
				_M_cache.erase(it);
				return false;
			}

			memcpy(ecname->cname, msg.name, msg.namelen);
			ecname->cnamelen = msg.namelen;
		}

		return make_request(ecname->name, ecname->namelen, (rr_type) ecname->type, true);
	} else {
		return false;
	}
}

bool resolver::parse_domain_name(msg& msg, char* name, unsigned short& namelen)
{
	unsigned short l = 0;

	const unsigned char* end;
	unsigned npointers = 0;

	do {
		unsigned char len = *msg.ptr;

		// Pointer?
		if ((len & 0xc0) == 0xc0) {
			// Too many compression pointers?
			if (npointers == MAX_COMPRESSION_POINTERS) {
				return false;
			}

			if (msg.ptr + 2 > msg.end) {
				return false;
			}

			if (npointers == 0) {
				end = msg.ptr + 2;
			}

			msg.ptr = msg.data + (((len & 0x3f) << 8) | msg.ptr[1]);
			if ((msg.ptr >= msg.end) || (msg.ptr < msg.data + sizeof(header))) {
				return false;
			}

			npointers++;
		} else {
			if (len == 0) {
				// If the domain name is empty...
				if (l == 0) {
					return false;
				}

				*name = 0; // NUL-terminate the domain name.
				namelen = l;

				if (npointers > 0) {
					msg.ptr = end;
				} else {
					msg.ptr++;
				}

				return true;
			} else {
				if (++msg.ptr + len >= msg.end) {
					return false;
				}

				// If the domain name is empty...
				if (l == 0) {
					if (l + len > NAME_MAX_LEN) {
						return false;
					}
				} else {
					if (l + 1 + len > NAME_MAX_LEN) {
						return false;
					}

					*name++ = '.';
					l++;
				}

				l += len;

				for (; len > 0; len--) {
					*name++ = *msg.ptr++;
				}
			}
		}
	} while (true);
}

bool resolver::find_first_record(msg& msg)
{
	msg.ptr = msg.data + sizeof(header);

	// Skip questions.
	for (unsigned short i = msg.h->qdcount; i > 0; i--) {
		if (!parse_domain_name(msg, msg.name, msg.namelen)) {
			return false;
		}

		// Skip QTYPE (2 bytes) and CLASS (2 bytes).
		if ((msg.ptr += 4) >= msg.end) {
			return false;
		}
	}

	return true;
}

bool resolver::find_next_record(msg& msg, rr& rr)
{
	if (!parse_domain_name(msg, rr.name, rr.namelen)) {
		return false;
	}

	if (msg.ptr + 10 > msg.end) {
		return NULL;
	}

	rr.type = ntohs(*((unsigned short*) msg.ptr));

	msg.ptr += 2;
	rr.cls = ntohs(*((unsigned short*) msg.ptr));

	msg.ptr += 2;
	rr.ttl = ntohl(*((unsigned*) msg.ptr));

	msg.ptr += 4;
	rr.rdlength = ntohs(*((unsigned short*) msg.ptr));

	msg.ptr += 2;

	if (msg.ptr + rr.rdlength > msg.end) {
		return NULL;
	}

	return true;
}

bool resolver::process_record(msg& msg, rr& rr)
{
	char name[NAME_MAX_LEN + 1];
	unsigned short namelen;
	short preference;

	switch (rr.type) {
		case (unsigned short) RR_TYPE_A:
			return process_a_record(msg, rr);
		case (unsigned short) RR_TYPE_CNAME:
			return process_cname_record(msg, rr, msg.cname, msg.cnamelen);
		case (unsigned short) RR_TYPE_PTR:
			return process_ptr_record(msg, rr, name, namelen);
		case (unsigned short) RR_TYPE_MX:
			return process_mx_record(msg, rr, preference, name, namelen);
		case (unsigned short) RR_TYPE_DNAME:
			return process_dname_record(msg, rr, name, namelen);
		default:
			msg.ptr += rr.rdlength;
	}

	return true;
}

bool resolver::process_a_record(msg& msg, rr& rr)
{
	if (rr.rdlength != 4) {
		return false;
	}

#if DEBUG
	const unsigned char* ip = msg.ptr;
	printf("IP address: %u.%u.%u.%u.\n", ip[0], ip[1], ip[2], ip[3]);
#endif // DEBUG

	if (msg.narecords < MAX_A_RECORDS) {
		struct address* address = &msg.arecords[msg.narecords++];

		address->addr = *((in_addr_t*) msg.ptr);
		address->expire = rr.ttl;
		address->preference = 0;

		msg.narecords++;
	}

	msg.ptr += rr.rdlength;

	return true;
}

bool resolver::process_cname_record(msg& msg, rr& rr, char* name, unsigned short& namelen)
{
	if (rr.rdlength < 2) {
		return false;
	}

	if (!parse_domain_name(msg, name, namelen)) {
		return false;
	}

	msg.type = rr.type;

#if DEBUG
	printf("CNAME: %s.\n", name);
#endif // DEBUG

	return true;
}

bool resolver::process_ptr_record(msg& msg, rr& rr, char* name, unsigned short& namelen)
{
	if (rr.rdlength < 2) {
		return false;
	}

	if (!parse_domain_name(msg, name, namelen)) {
		return false;
	}

#if DEBUG
	printf("PTR: %s.\n", name);
#endif // DEBUG

	return true;
}

bool resolver::process_mx_record(msg& msg, rr& rr, short& preference, char* name, unsigned short& namelen)
{
	if (rr.rdlength < 4) {
		return false;
	}

	preference = ntohs(*((short*) msg.ptr));

	msg.ptr += 2;

	if (!parse_domain_name(msg, name, namelen)) {
		return false;
	}

#if DEBUG
	printf("MX: %s, preference: %d.\n", name, preference);
#endif // DEBUG

	return true;
}

bool resolver::process_dname_record(msg& msg, rr& rr, char* name, unsigned short& namelen)
{
	msg.ptr += rr.rdlength;

	return true;
}

bool resolver::dns_entry::init(const char* n, unsigned short l, rr_type rr_type, time_t t)
{
	if ((name = (char*) malloc(l)) == NULL) {
		return false;
	}

	memcpy(name, n, l);
	namelen = l;

	type = (unsigned short) rr_type;

	recursion = 0;

	timestamp = t;

	status = STATUS_WAITING;

	naddresses = 0;
	cnamelen = 0;

	return true;
}
