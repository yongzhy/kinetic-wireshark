#ifndef __wireshark_glue_kinetic_h__
#define __wireshark_glue_kinetic_h__

#include <string>
#include <list>

extern "C" {

///////////////////////////////////////////////////////////////////////////////////
// Following are definitions that are from wireshark. The necessary headers are
// not included here to minimize dependencies of glue code
//////////////////////////////////////////////////////////////////////////////////
struct tvbuff_t;
struct proto_tree;
struct proto_item;

// Following enum should match wireshark/epan/ftypes/ftypes.h
enum ftenum {
  FT_NONE,  /* used for text labels with no value */
  FT_PROTOCOL,
  FT_BOOLEAN, /* TRUE and FALSE come from <glib.h> */
  FT_UINT8,
  FT_UINT16,
  FT_UINT24,  /* really a UINT32, but displayed as 6 hex-digits if FD_HEX*/
  FT_UINT32,
  FT_UINT40,  /* really a UINT64, but displayed as 10 hex-digits if FD_HEX*/
  FT_UINT48,  /* really a UINT64, but displayed as 12 hex-digits if FD_HEX*/
  FT_UINT56,  /* really a UINT64, but displayed as 14 hex-digits if FD_HEX*/
  FT_UINT64,
  FT_INT8,
  FT_INT16,
  FT_INT24, /* same as for UINT24 */
  FT_INT32,
  FT_INT40, /* same as for UINT40 */
  FT_INT48, /* same as for UINT48 */
  FT_INT56, /* same as for UINT56 */
  FT_INT64,
  FT_IEEE_11073_SFLOAT,
  FT_IEEE_11073_FLOAT,
  FT_FLOAT,
  FT_DOUBLE,
  FT_ABSOLUTE_TIME,
  FT_RELATIVE_TIME,
  FT_STRING,
  FT_STRINGZ, /* for use with proto_tree_add_item() */
  FT_UINT_STRING, /* for use with proto_tree_add_item() */
  FT_ETHER,
  FT_BYTES,
  FT_UINT_BYTES,
  FT_IPv4,
  FT_IPv6,
  FT_IPXNET,
  FT_FRAMENUM,  /* a UINT32, but if selected lets you go to frame with that number */
  FT_PCRE,  /* a compiled Perl-Compatible Regular Expression object */
  FT_GUID,  /* GUID, UUID */
  FT_OID,   /* OBJECT IDENTIFIER */
  FT_EUI64,
  FT_AX25,
  FT_VINES,
  FT_REL_OID, /* RELATIVE-OID */
  FT_SYSTEM_ID,
  FT_STRINGZPAD,  /* for use with proto_tree_add_item() */
  FT_FCWWN,
  FT_NUM_TYPES /* last item number plus one */  
};

extern proto_item* proto_tree_add_item( void *tree, int handle, void * tvb,
                                 int offset, int length, bool b );
extern proto_item* proto_tree_add_none_format( void *tree, int handle, void * tvb,
					       int offset, int length, const char* format, ...);
extern proto_item* proto_tree_add_uint( void *tree, int handle, void * tvb,
                                 int offset, int length, unsigned int b );
extern proto_item* proto_tree_add_uint64( void *tree, int handle, void * tvb,
                                 int offset, int length, unsigned long long b );
extern proto_item* proto_tree_add_int( void *tree, int handle, void * tvb,
                                 int offset, int length, int b );
extern proto_item* proto_tree_add_int64( void *tree, int handle, void * tvb,
                                 int offset, int length, long long b );
extern proto_item* proto_tree_add_float( void *tree, int handle, void * tvb,
                                 int offset, int length, float b );
extern proto_item* proto_tree_add_double( void *tree, int handle, void * tvb,
                                 int offset, int length, double b );
extern proto_item* proto_tree_add_boolean( void *tree, int handle, void * tvb,
                                 int offset, int length, unsigned b );
extern proto_item* proto_tree_add_text( void *tree, void * tvb,
                                int offset, int length, const char* b, ... );
extern proto_item* proto_tree_add_int_format_value(void *tree, int handle, 
						   void *tvb, int offset, 
						   int length, int value, 
						   const char *format, ...);
extern proto_item* proto_tree_add_string( void *tree, int handle, void *tvb,
					  int offset, int length, 
					  const char* value );
extern proto_item* proto_tree_add_bytes( void *tree, int handle, void *tvb,
            int offset, int length, 
            const char* value );
extern proto_tree* proto_item_add_subtree( void * item, int tree_handle );

// end of wireshark definitions

///////////////////////////////////////////////////////////////////////////////////
// following functions are implemented in packet-|PLUGIN|.c code
//////////////////////////////////////////////////////////////////////////////////
extern int wireshark_pb_add_kinetic(void* tree_root, void *tvb, int item_id, char* msg_str);
extern void wireshark_pb_process_kinetic_register_subtree( int proto, const char* name,
                                                int *handle, int ** tree_handle );
extern void wireshark_pb_process_kinetic_register_field( int proto, int type,
                                                const char* name, const char * fullName,
                                                int *handle );

///////////////////////////////////////////////////////////////////////////////////
// rest of definitions are specific to the glue file
//////////////////////////////////////////////////////////////////////////////////

//fwd declarations
namespace google
{
namespace protobuf
{
class Descriptor;
class FieldDescriptor;
class Message;
class Reflection;
}
}

class kinetic_Dissector;
struct Handles;

typedef std::pair<std::string, Handles> StringHandlePair;
typedef std::map<std::string, Handles> HandleMap;

typedef std::vector<const google::protobuf::Descriptor*> DescriptorList;
typedef std::vector<const google::protobuf::FieldDescriptor*> FieldDescriptorList;

typedef std::list<kinetic_Dissector> DissectorList;

// this is the main dissector class which hold context during dissection of message

class kinetic_Dissector
{  

public: // methods

  // default ctor to satisfy std::list
  kinetic_Dissector();

  // actual ctor that is used
  kinetic_Dissector( proto_tree* tree, int offset, 
			   const google::protobuf::Message* mess, 
			   const google::protobuf::FieldDescriptor* field, int index = -1 );

  // main dissect method
  void dissect( DissectorList& list );

protected: // methods

  // dissect a basic field
  void dissectField( const google::protobuf::FieldDescriptor* field );

  // dissect a repeated field
  void dissectRepeatedField( const google::protobuf::FieldDescriptor* field, int index );

  // returns total length of message as seen in byte stream
  // this will be data size + encoding length of tag + data_size length
  int messageLength()
  {
    return _len;
  }

private: // data

  // the leaf tree for this message and subfields
  proto_tree* _leaf;

  // total length of message including overhead
  int _len;

  // message pointer
  const google::protobuf::Message* _message;

  // offset into tvb
  int _offset;

  // size of overhead
  int _prefix_len;  

  // reflection pointer cache
  const google::protobuf::Reflection* _reflection;

};

typedef struct Handles
{
   int handle;
   int * tree_handle;

   Handles() : handle( -1 ), tree_handle( NULL ) {}
} Handles;

#define DBG( x ) { std::cout << x << std::endl; }
#define DBG_ERR( x ) { std::cerr << x << std::endl; }

} // of extern "C"

#endif

