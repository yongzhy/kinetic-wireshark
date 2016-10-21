#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gmodule.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tvbuff.h>
//#include <epan/emem.h>
#include <string.h>
#include <epan/dissectors/packet-tcp.h> 
#include <stdio.h>

/* forward reference */

void proto_register_kinetic(void);
void proto_reg_handoff_kinetic(void);
static int dissect_kinetic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
static int dissect_kinetic_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);


/* Define version if we are not building ethereal statically */
#ifndef ENABLE_STATIC
WS_DLL_PUBLIC_DEF const gchar version[] = VERSION;
#endif


static int proto_kinetic = -1;
static int global_kinetic_udp_ports[] = 
{ 
    8123 
};
static int global_kinetic_tcp_ports[] = 
{ 
    8123 
};

static dissector_handle_t kinetic_handle_tcp;
static dissector_handle_t kinetic_handle_udp;

// Protocol field variables - START
static int hf_kinetic = -1;
// Protocol field variables - END

int wireshark_pb_process_kinetic(void *tree_root, int item_id, void *tvb,  void *buf, int buf_size, char* col_info);
int wireshark_pb_process_kinetic_value(proto_tree* tree_root, tvbuff_t* tvb, void* buf, int buf_size);
void wireshark_pb_process_kinetic_register_proto( int proto );
void wireshark_pb_process_kinetic_register_subtree( int proto, const char* name,
                                                int *handle, int ** tree_handle );
void wireshark_pb_process_kinetic_register_field( int proto, int type,
                                                const char* name, const char * fullName, int *handle );

/* Register plugin - START */
#ifndef ENABLE_STATIC
WS_DLL_PUBLIC_DEF void plugin_register(void) { 
  /* register the new protocol, protocol fields, and subtrees */
  if (proto_kinetic == -1) { /* execute protocol initialization only once */
    proto_register_kinetic();
  }
}

WS_DLL_PUBLIC_DEF void plugin_reg_handoff(void){
  proto_reg_handoff_kinetic();
}
#endif

void proto_register_kinetic(void) {

  //module_t *kinetic_module;
  if (proto_kinetic == -1) {
    proto_kinetic = proto_register_protocol (
        "Kinetic Protocol", /* name */
        "Kinetic",          /* short name */
        "kinetic"           /* abbrev */
      );
    }
  //kinetic_module= prefs_register_protocol(proto_kinetic, proto_reg_handoff_kinetic);
  prefs_register_protocol(proto_kinetic, proto_reg_handoff_kinetic);

  wireshark_pb_process_kinetic_register_proto( proto_kinetic );
}

void proto_reg_handoff_kinetic (void) {
  static int Initialized=FALSE;
  unsigned int i = 0;

  if (!Initialized) {
    kinetic_handle_tcp = create_dissector_handle(dissect_kinetic, proto_kinetic);
    kinetic_handle_udp = create_dissector_handle(dissect_kinetic_udp, proto_kinetic);

    for( ; i < ( sizeof( global_kinetic_tcp_ports ) / sizeof( global_kinetic_tcp_ports[0] ) ); i++) {
      dissector_add_uint("tcp.port", global_kinetic_tcp_ports[i], kinetic_handle_tcp);
    }       
    for( ; i < ( sizeof( global_kinetic_udp_ports ) / sizeof( global_kinetic_udp_ports[0] ) ); i++) {
      dissector_add_uint("udp.dstport", global_kinetic_udp_ports[i], kinetic_handle_udp);
    }
  }
}
/* Register plugin - END */

/* Generate the main dissector function - START */
static int dissect_kinetic_tcp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Kinetic");

  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo,COL_INFO);

  if (tree) { /* we are being asked for details */
    unsigned int pkt_len = tvb_captured_length(tvb);
    if(pkt_len>0)
    {
      if( pkt_len>9 && tvb_get_guint8(tvb, 0)=='F')  // Kintic Message Start Frame
      {
        char col_info[1024] = {'\0'};
        gint msg_len = tvb_get_ntohl(tvb, 1);  
        gint total_value_len = tvb_get_ntohl(tvb, 5); 
        gint frame_value_len = pkt_len - 9 - msg_len; 
        proto_item * ti = NULL;  
        tvbuff_t * next_tvb = tvb_new_subset_remaining (tvb,9);  

        ti = proto_tree_add_item(tree,proto_kinetic,tvb,0,9,ENC_NA);  
        proto_item_append_text(ti, ", Message Length %d(0x%08X), Total Value Length %d(0x%08X), Frame Value Length %d(0x%08X)",
                  msg_len, msg_len, total_value_len, total_value_len, frame_value_len, frame_value_len); 

        wireshark_pb_process_kinetic((void *) tree, hf_kinetic, 
          (void *)next_tvb,  (void *)tvb_get_ptr(next_tvb,0,msg_len), msg_len, col_info);

        if(frame_value_len > 0) 
        {
          tvbuff_t * value_tvb = tvb_new_subset_remaining (tvb,9 + msg_len); 
          wireshark_pb_process_kinetic_value((void *) tree,  
            (void *)value_tvb,  (void *)tvb_get_ptr(value_tvb,0, frame_value_len), frame_value_len);
        }

        col_set_str(pinfo->cinfo, COL_INFO, col_info);
      }
      else // Network packet for Kinetic Value
      {
        proto_item * ti = NULL; 
        ti = proto_tree_add_item(tree,proto_kinetic,tvb,0,9,ENC_NA);  
        proto_item_append_text(ti, ", Frame Value Length %d(0x%08X)",pkt_len, pkt_len); 
        wireshark_pb_process_kinetic_value((void *) tree,  
          (void *)tvb,  (void *)tvb_get_ptr(tvb,0, pkt_len), pkt_len);
        col_set_str(pinfo->cinfo, COL_INFO, "Kinetic Value");
      }
    }
  }

  return tvb_captured_length(tvb);

} //dissect_kinetic_tcp

static guint get_kinetic_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset, void* data _U_)  
{  
    /* TODO: change this to your needs */  
    if(pinfo != NULL) {

    }
    return tvb_captured_length(tvb);  
}  

static int dissect_kinetic_udp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) 
{
  printf("Packet %d Protocol Port Type = %d\n", pinfo->fd->num, pinfo->ptype);
  col_set_str(pinfo->cinfo, COL_INFO, "Kinetic Broadcast"); // Not sure why not work
  return tvb_captured_length(tvb);
}

/* Generate the main dissector function - START */
static int dissect_kinetic (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) 
{
  if( pinfo->ptype == PT_UDP)
  {  
      //dissect_kinetic_tcp(tvb,pinfo,tree, data);  
      col_set_str(pinfo->cinfo, COL_INFO, "Kinetic Broadcast"); // Not sure why not work
      return tvb_captured_length(tvb);
  }
  else  
  {  
      tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 9,  
                       get_kinetic_message_len, dissect_kinetic_tcp, data);  
      return tvb_captured_length(tvb);
  }  
  return tvb_captured_length(tvb);

} //dissect_kinetic
/* Generate the main dissector function - END */


/** Called from PB to add msg_str to tree_root */
int wireshark_pb_add_kinetic(void* tree_root, void* tvb, int item_id, char* msg_str) {
  proto_tree_add_none_format ((proto_tree *) tree_root, item_id, (tvbuff_t*) tvb, 0, -1, msg_str);
  return 0;
}

void wireshark_pb_process_kinetic_register_subtree( int proto, const char* name,
     int *handle, int ** p_tree_handle )
{
  hf_register_info message_info =
  { handle,
      { (char*)name,
        (char*)name,
                FT_NONE,
                BASE_NONE,
                NULL, 0,
                "",
                HFILL
      }
  };
  
  int * tree_handle;
  
  hf_register_info *hf_info = (hf_register_info*)malloc(sizeof( hf_register_info ) );  

  *hf_info = message_info;

  proto_register_field_array( proto, hf_info, 1 );

  tree_handle = (int*)malloc( sizeof(int) );
  *tree_handle = -1;

  proto_register_subtree_array( &tree_handle, 1 );

  *p_tree_handle = tree_handle;
}

int wireshark_pb_number_base(int type)
{
  int base = BASE_NONE;
  switch(type) {
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT32:
    case FT_UINT48:
    case FT_UINT56:
    case FT_UINT64:
      base = BASE_HEX;
      break;
    case FT_INT8:
    case FT_INT16:
    case FT_INT32:
    case FT_INT48:
    case FT_INT56:
    case FT_INT64:
      base = BASE_DEC;
      break;
    default:
      base = BASE_NONE;
      break;
  } 
  return base;

}

void wireshark_pb_process_kinetic_register_field( int proto, int type,
                    const char* name, const char * fullName, int *handle )
{
  int base = wireshark_pb_number_base(type);
  hf_register_info message_info =
  { handle,
      { (char*)fullName,
        (char*)name,
                (enum ftenum)type,
                base,
                NULL, 0,
                "",
                HFILL
      }
  };

  hf_register_info *hf_info = (hf_register_info*)malloc(sizeof( hf_register_info ) );

  *hf_info = message_info;

  proto_register_field_array( proto, hf_info, 1 );
}
