#ifndef RESOLVER_H
#define RESOLVER_H

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "red_black_tree.h"
#include "macros.h"

#define NAME_MAX_LEN         255
#define UDP_MESSAGE_MAX_SIZE 512
#define MAX_A_RECORDS        50

class resolver {
	public:
		enum query_type {
			QUERY_STANDARD = 0,
			QUERY_INVERSE = 1
		};

		// Type of resource record.
		enum rr_type {
			RR_TYPE_A = 1,
			RR_TYPE_CNAME = 5,
			RR_TYPE_PTR = 12,
			RR_TYPE_MX = 15,
			RR_TYPE_DNAME = 39
		};

		// Constructor.
		resolver();

		// Destructor.
		virtual ~resolver();

		// Resolve.
		bool resolve(const char* name, rr_type type);
		bool resolve(const char* name, size_t namelen, rr_type type);

	protected:
		static const unsigned short DNS_SERVER_PORT;
		static const size_t LABEL_MAX_LEN;
		static const unsigned MAX_RECURSION;
		static const unsigned MAX_COMPRESSION_POINTERS;
		static const unsigned TTL_NO_DOMAIN;

		enum query_status {
			STATUS_WAITING,
			STATUS_NO_DOMAIN,
			STATUS_VALID
		};

		struct header {
			unsigned short id;

			union {
				struct {
					unsigned short rcode:4;
					unsigned short z:3;
					unsigned short ra:1;
					unsigned short rd:1;
					unsigned short tc:1;
					unsigned short aa:1;
					unsigned short opcode:4;
					unsigned short qr:1;
				};

				unsigned short flags;
			};

			unsigned short qdcount;
			unsigned short ancount;
			unsigned short nscount;
			unsigned short arcount;
		};

		// Resource record.
		struct rr {
			char name[NAME_MAX_LEN + 1];
			unsigned short namelen;

			unsigned short type;
			unsigned short cls;

			unsigned ttl;

			unsigned short rdlength;
		};

		struct address {
			in_addr_t addr;
			time_t expire;
			short preference;
		};

		// DNS cache entry.
		struct dns_entry {
			char* name;
			unsigned short namelen;

			unsigned short type;
			unsigned short recursion;

			time_t timestamp;

			unsigned char status;

			union {
				struct address address;
				struct address* addresses;
				char* cname;
			};

			unsigned short naddresses;
			unsigned short cnamelen;

			bool init(const char* n, unsigned short l, rr_type rr_type, time_t t);

			static void destroy(dns_entry* e);
			void destroy_addresses();

			bool operator<(const struct dns_entry& e) const;
			int operator-(const struct dns_entry& e) const;
		};

		// UDP message.
		struct msg {
			unsigned char data[UDP_MESSAGE_MAX_SIZE];
			const unsigned char* end;
			header* h;
			const unsigned char* ptr;

			char name[NAME_MAX_LEN + 1];
			unsigned short namelen;

			unsigned short type;

			struct address arecords[MAX_A_RECORDS];
			unsigned short narecords;

			char cname[NAME_MAX_LEN + 1];
			unsigned short cnamelen;
		};

		unsigned short _M_id;

		// DNS cache.
		red_black_tree<dns_entry> _M_cache;

		// Make request.
		bool make_request(const char* name, size_t namelen, rr_type type, bool in_cache);

		// Add to cache.
		bool add_to_cache(const char* name, size_t namelen, rr_type type, red_black_tree<dns_entry>::iterator* it = NULL);

		// Fill header.
		void fill_header(header* h, query_type type);

		// Fill question.
		static bool fill_question(const char* name, size_t namelen, rr_type type, unsigned char* buf, size_t& size);

		// Parse message.
		bool parse_message(msg& msg);

		// Find.
		bool find(const char* name, size_t namelen, red_black_tree<dns_entry>::iterator& it);

		// Parse header.
		static bool parse_header(msg& msg);

		// Parse domain name.
		static bool parse_domain_name(msg& msg, char* name, unsigned short& namelen);

		// Find first resource record.
		static bool find_first_record(msg& msg);

		// Find next resource record.
		static bool find_next_record(msg& msg, rr& rr);

		// Process resource record.
		static bool process_record(msg& msg, rr& rr);

		// Process A resource record.
		static bool process_a_record(msg& msg, rr& rr);

		// Process CNAME record.
		static bool process_cname_record(msg& msg, rr& rr, char* name, unsigned short& namelen);

		// Process PTR record.
		static bool process_ptr_record(msg& msg, rr& rr, char* name, unsigned short& namelen);

		// Process MX record.
		static bool process_mx_record(msg& msg, rr& rr, short& preference, char* name, unsigned short& namelen);

		// Process DNAME record.
		static bool process_dname_record(msg& msg, rr& rr, char* name, unsigned short& namelen);
};

inline bool resolver::resolve(const char* name, rr_type type)
{
	return resolve(name, strlen(name), type);
}

inline void resolver::fill_header(header* h, query_type type)
{
	h->id = htons(++_M_id);
	h->flags = htons((type << 12) | (1 << 8));
	h->qdcount = htons(1); // Number of questions.
	h->ancount = 0;
	h->nscount = 0;
	h->arcount = 0;
}

inline bool resolver::find(const char* name, size_t namelen, red_black_tree<dns_entry>::iterator& it)
{
	dns_entry entry;
	entry.name = const_cast<char*>(name);
	entry.namelen = namelen;
	return _M_cache.find(entry, it);
}

inline bool resolver::parse_header(msg& msg)
{
	msg.h->id = ntohs(msg.h->id);
	msg.h->flags = ntohs(msg.h->flags);
	msg.h->qdcount = ntohs(msg.h->qdcount);
	msg.h->ancount = ntohs(msg.h->ancount);
	msg.h->nscount = ntohs(msg.h->nscount);
	msg.h->arcount = ntohs(msg.h->arcount);

	return ((msg.h->qr) && (!msg.h->tc) && (msg.h->qdcount > 0));
}

inline void resolver::dns_entry::destroy(dns_entry* e)
{
	free(e->name);
	e->destroy_addresses();

	if (e->cnamelen > 0) {
		free(e->cname);
	}
}

inline void resolver::dns_entry::destroy_addresses()
{
	if (naddresses > 1) {
		free(addresses);
	}

	naddresses = 0;
}

inline bool resolver::dns_entry::operator<(const struct dns_entry& e) const
{
	return (operator-(e) < 0);
}

inline int resolver::dns_entry::operator-(const struct dns_entry& e) const
{
	unsigned short l = MIN(namelen, e.namelen);
	int ret = memcmp(name, e.name, l);
	if (ret < 0) {
		return -1;
	} else if (ret == 0) {
		if (namelen < e.namelen) {
			return -1;
		} else if (namelen == e.namelen) {
			return 0;
		} else {
			return 1;
		}
	} else {
		return 1;
	}
}

#endif // RESOLVER_H
