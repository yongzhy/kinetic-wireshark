#include "kinetic.pb.h"
#include "wireshark-glue-kinetic.h"

#include <iostream>

#include <google/protobuf/text_format.h>
#include <google/protobuf/wire_format.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/io/coded_stream.h>
#include <stdio.h>
#include <map>

using namespace std;
using namespace google;
using namespace protobuf;
using namespace internal;

extern "C" {

static HandleMap* handleMap = NULL;

static void * _tvb = NULL;

static const char ARRAY_FORMAT[] = "%s[%d]";

static const char KineticValueFiled[] = "KineticValue";

/**
  * @param buf The message contents
  * @param buf_size The length of message contents in buf
  * @param tree_root The WireShark tree to which this message is to be added.
  * @param item_id Internal wireshark id to refer to this FT_NONE datatype.
  */
int wireshark_pb_process_kinetic(proto_tree* tree_root, int item_id, tvbuff_t* tvb, void* buf, int buf_size, char* col_info) {

  com::seagate::kinetic::proto::Message msg;
  if (!msg.ParseFromArray((char *) buf, buf_size)) {
    DBG_ERR( "Failed to parse message." );

    // for (int i=0; i < (buf_size>160?160:buf_size); i++) {
    //   if(i%16==0) {
    //     printf("\n");
    //   }
    //   printf("%02x ", ((unsigned char *)buf)[i]);
    // }
    // printf("buf size=%d\n", buf_size);
    // printf("%s\n\n\n", buf);

    return -1;
  }

  // store tvb for subsequent calls
  _tvb = tvb;

  int offset = 0; 

  DissectorList dissectorList;

  // we process the message tree breadth wise
  dissectorList.push_back( kinetic_Dissector( tree_root, offset, &msg, NULL ) );
  
  while ( !dissectorList.empty() )
  {
    kinetic_Dissector dissector = dissectorList.front();
    dissectorList.pop_front();

    // this can add further entries to message dissector list
    dissector.dissect( dissectorList );
  } // while( !dissectorList.empty() )

  com::seagate::kinetic::proto::Command command;
  if(!command.ParseFromString(msg.commandbytes())) {
    return -1;
  }

  // Calculate the offset for commandbytes in the message serialized buffer
  offset = buf_size - msg.commandbytes().size();
  // we process the message tree breadth wise
  dissectorList.push_back( kinetic_Dissector( tree_root, offset, &command, NULL ) );
  
  while ( !dissectorList.empty() )
  {
    kinetic_Dissector dissector = dissectorList.front();
    dissectorList.pop_front();

    // this can add further entries to message dissector list
    dissector.dissect( dissectorList );
  } // while( !dissectorList.empty() )

  if(msg.authtype() == com::seagate::kinetic::proto::Message_AuthType_UNSOLICITEDSTATUS)
  {
    sprintf(col_info, "Kinetic Message: UNSOLICITEDSTATUS");
  }
  else
  {
    sprintf(col_info, "Kinetic Command: %s", com::seagate::kinetic::proto::Command_MessageType_Name(command.header().messagetype()).c_str());
  }

  return 0;
}

/**
  * @param buf The message contents
  * @param buf_size The length of message contents in buf
  * @param tree_root The WireShark tree to which this message is to be added.
  * @param item_id Internal wireshark id to refer to this FT_NONE datatype.
  */
int wireshark_pb_process_kinetic_value(proto_tree* tree_root, tvbuff_t* tvb, void* buf, int buf_size) {

    HandleMap::iterator it = handleMap->find( KineticValueFiled );

    if( it == handleMap->end() ) 
    {
      DBG_ERR( "couldnt find handle for " << KineticValueFiled );
      return -1;
    }

    Handles handles = it->second;

    proto_tree_add_bytes( tree_root, handles.handle, tvb, 0, buf_size,  
             (const char*)buf );  

    return 0;  
}


void wireshark_pb_process_kinetic_register_subtree_( int proto, 
                 const std::string& name,
                 const std::string& full_name )
{
    Handles handles;
    wireshark_pb_process_kinetic_register_subtree( proto,
              name.c_str(),
              &(handles.handle), &(handles.tree_handle) );
    handleMap->insert( StringHandlePair( full_name, handles ) );
}

int wireshark_pb_process_kinetic_get_type( FieldDescriptor::CppType type )
{
  struct ftmap_t
  {
    FieldDescriptor::CppType cpp_type;
    ftenum fttype;
    int length;
  };

  static ftmap_t ftmap[] = {
     { FieldDescriptor::CPPTYPE_UINT32, FT_UINT32 },
     { FieldDescriptor::CPPTYPE_INT32, FT_INT32 },
     { FieldDescriptor::CPPTYPE_UINT64, FT_UINT64 },
     { FieldDescriptor::CPPTYPE_INT64, FT_INT64 },
     { FieldDescriptor::CPPTYPE_DOUBLE, FT_DOUBLE },
     { FieldDescriptor::CPPTYPE_FLOAT, FT_FLOAT },
     { FieldDescriptor::CPPTYPE_BOOL, FT_BOOLEAN },
     { FieldDescriptor::CPPTYPE_ENUM, FT_INT32 }, 
     { FieldDescriptor::CPPTYPE_STRING, FT_STRINGZ } };

  for( int i =0; i < sizeof(ftmap)/sizeof(ftmap_t); i++ )
  {
     if( ftmap[i].cpp_type == type ) 
     {
       return ftmap[i].fttype;
     }
  } 

  DBG_ERR( "Couldnt find type for cpp type " << type );
  return FT_NONE;
}

void wireshark_pb_process_kinetic_register_proto( int proto )
{
  if( handleMap == NULL )
  {
    handleMap = new HandleMap();
  }

  std::map<std::string, bool> messageMap;

  DescriptorList messageDescriptorList;
  FieldDescriptorList fieldDescriptorList;
  
  // we process the message definition depth first
  const Descriptor* desc = com::seagate::kinetic::proto::Message::descriptor();
  messageDescriptorList.push_back( desc );
  messageMap.insert(std::pair<std::string, bool>(desc->full_name(), true));

  const Descriptor* cmd_desc = com::seagate::kinetic::proto::Command::descriptor();
  messageDescriptorList.push_back( cmd_desc );
  messageMap.insert(std::pair<std::string, bool>(cmd_desc->full_name(), true));

  while( !messageDescriptorList.empty() )
  {
    const Descriptor* messageDescriptor = messageDescriptorList.back();
    messageDescriptorList.pop_back();    
    
    //DBG( "Register message ( " << messageDescriptor->full_name() << " )" );
    
    wireshark_pb_process_kinetic_register_subtree_( proto, 
                messageDescriptor->name(), 
                messageDescriptor->full_name() );
    
    for( int i = 0; i < messageDescriptor->field_count(); i++ )
    {
      const FieldDescriptor* fieldDescriptor = messageDescriptor->field( i );
      
      if( fieldDescriptor->cpp_type() == FieldDescriptor::CPPTYPE_MESSAGE )
      {
        if(messageMap.find(fieldDescriptor->full_name()) == messageMap.end()) 
        {
          messageDescriptorList.push_back( fieldDescriptor->message_type() );
          messageMap.insert(std::pair<std::string, bool>(fieldDescriptor->full_name(), true));
        }
      }
      else
      {
        fieldDescriptorList.push_back( fieldDescriptor );
      }
    }
  }
  
  // process all field descriptors at very end
  while( !fieldDescriptorList.empty() )
  {
    const FieldDescriptor* fieldDescriptor = fieldDescriptorList.back();
    fieldDescriptorList.pop_back();

    Handles handles;
    //DBG( "Register field ( " << fieldDescriptor->name() << " : " << fieldDescriptor->full_name() << " )" );
    wireshark_pb_process_kinetic_register_field( proto, 
                   wireshark_pb_process_kinetic_get_type( fieldDescriptor->cpp_type() ),
                   fieldDescriptor->name().c_str(),
                   fieldDescriptor->name().c_str(),
                   &(handles.handle) );
    handleMap->insert( StringHandlePair( fieldDescriptor->full_name(), handles ) );
  }

  {
    Handles handles;
    //DBG( "Register field ( " << KineticValueFiled << " )" );
    wireshark_pb_process_kinetic_register_field( proto, 
                   FT_BYTES,
                   KineticValueFiled,
                   KineticValueFiled,
                   &(handles.handle) );
    handleMap->insert( StringHandlePair( KineticValueFiled, handles ) );
  }  
}

kinetic_Dissector::kinetic_Dissector()
  : _leaf( NULL ),
    _len( -1 ),
    _message( NULL ),
    _offset( 0 ),
    _prefix_len( -1 ),
    _reflection( NULL )
{
}

  
kinetic_Dissector::kinetic_Dissector( proto_tree* tree, int offset,
              const Message* message, 
              const FieldDescriptor* field,
              int index )
  : _leaf( NULL ),
    _len( -1 ),
    _message( message ),
    _offset( offset ),
    _prefix_len( 0 ),
    _reflection( _message->GetReflection() )
{
    bool is_root = ( field == NULL );
    const std::string& label = ( is_root ) ? _message->GetDescriptor()->name() : field->name();
    const std::string& fullname = _message->GetDescriptor()->full_name();

    int data_size = _message->ByteSize();  
    int total_size = data_size;
      
    // if not root field then prefix_len needs to be computed
    if( !is_root )
    {
      _prefix_len = WireFormat::TagSize( _message->GetDescriptor()->index(), 
           FieldDescriptor::TYPE_MESSAGE );
      _prefix_len+= io::CodedOutputStream::VarintSize32( data_size );
      total_size+= _prefix_len;
    }

    _len = total_size;

    // construct subtree here itself rather than in dissect method otherwise
    // all repeated fields and messages are pushed to end of current tree
    // regardless of their current position
    HandleMap::iterator it = handleMap->find( fullname );

    if( it == handleMap->end() ) 
    {
      DBG_ERR( "couldnt find handle for " << fullname );
      return;
    }

    Handles handles = it->second;

    // add a subtree for current message
    proto_item* item;
    if( index == -1 )
    {
      item = proto_tree_add_none_format( tree, handles.handle, _tvb, 
           _offset, _len, 
           label.c_str() );
    }
    else
    {
      item = proto_tree_add_none_format( tree, handles.handle, _tvb, 
           _offset, _len, ARRAY_FORMAT, 
           label.c_str(), index );
      
    }
    _leaf = proto_item_add_subtree( item, *(handles.tree_handle) );
}

void kinetic_Dissector::dissect( DissectorList& dissectorList )
{
  //DBG( "Dissecting " << _message->GetDescriptor()->name() 
  //   << " of length " << _len
  //   << " prefix len " << _prefix_len );

  if( !_leaf )
  {
    DBG_ERR( "Couldnt find leaf node for current message" );
    return;
  } 

  _offset+= _prefix_len;

  // now loop through all the field in current message

  FieldDescriptorList fields ;

  _reflection->ListFields( *_message, &fields );
  
  for( FieldDescriptorList::iterator it = fields.begin(); it!=fields.end(); it++ )
  {
    const FieldDescriptor* field = *it;
    bool is_message = ( field->cpp_type() == FieldDescriptor::CPPTYPE_MESSAGE ) ;

    if( field->is_repeated() )
    {
      if( field->options().packed() )
      {
        int data_size = WireFormat::FieldDataOnlyByteSize( field, *_message );
        if (data_size > 0) 
        {
          _offset += WireFormat::TagSize( field->number(), FieldDescriptor::TYPE_STRING );
          _offset += io::CodedOutputStream::VarintSize32( data_size );
        }
      }

      int size = _reflection->FieldSize( *_message, field );
      for( int i = 0; i < size; i++ )
      {
        if( is_message )
        {
          const Message& subMessage = _reflection->GetRepeatedMessage( *_message, 
                       field, i );
          kinetic_Dissector dissector( _leaf, _offset,
                     &subMessage, field, i );
          dissectorList.push_back( dissector );
          _offset+= dissector.messageLength();
        }
        else
        {
          dissectRepeatedField( field, i );
        }
      }
    } 
    else if( is_message )
    {
      const Message& subMessage = _reflection->GetMessage( *_message, field );
      kinetic_Dissector dissector( _leaf, _offset,
                 &subMessage, field ); 
      dissectorList.push_back( dissector );
      _offset+= dissector.messageLength();
    }
    else // plain simple field. process it immediately
    {
      dissectField( field );
    }
  }
}

void kinetic_Dissector::dissectField( const FieldDescriptor* field )
{
    int len = WireFormat::FieldByteSize( field, *_message );

    //DBG( "Dissecting field " << field->name() << " " << len );

    HandleMap::iterator it = handleMap->find( field->full_name() );

    if( it == handleMap->end() ) 
    {
      DBG_ERR( "Couldnt find handle for " << field->full_name() );
      return;
    }

    Handles handles = it->second;

    const EnumValueDescriptor* enumDesc = NULL;

    switch( field->cpp_type() )
    {
      case FieldDescriptor::CPPTYPE_UINT32:
        proto_tree_add_uint( _leaf, handles.handle, _tvb, _offset, len,
           _reflection->GetUInt32( *_message, field ) );
        break;
      case FieldDescriptor::CPPTYPE_INT32:
        proto_tree_add_int( _leaf, handles.handle, _tvb, _offset, len, 
          _reflection->GetInt32( *_message, field ) );
        break;
      case FieldDescriptor::CPPTYPE_FLOAT:
        proto_tree_add_float( _leaf, handles.handle, _tvb, _offset, len, 
            _reflection->GetFloat( *_message, field ) );
        break;
      case FieldDescriptor::CPPTYPE_UINT64:
        proto_tree_add_uint64( _leaf, handles.handle, _tvb, _offset, len, 
             _reflection->GetUInt64( *_message, field ) );
        break;
      case FieldDescriptor::CPPTYPE_INT64:
        proto_tree_add_int64( _leaf, handles.handle, _tvb, _offset, len, 
            _reflection->GetInt64( *_message, field ) );
        break;
      case FieldDescriptor::CPPTYPE_DOUBLE:
        proto_tree_add_double( _leaf, handles.handle, _tvb, _offset, len, 
             _reflection->GetDouble( *_message, field ) );
        break;
      case FieldDescriptor::CPPTYPE_BOOL:
        proto_tree_add_boolean( _leaf, handles.handle, _tvb, _offset, len, 
              _reflection->GetBool( *_message, field ) );
        break;
      case FieldDescriptor::CPPTYPE_ENUM:
        enumDesc = _reflection->GetEnum( *_message, field );
        proto_tree_add_int_format_value( _leaf, handles.handle, _tvb, _offset, len, 
                 enumDesc->number(), "%d ( %s )", enumDesc->number(),
                 enumDesc->name().c_str() );
        break;
      case FieldDescriptor::CPPTYPE_STRING:
        proto_tree_add_string( _leaf, handles.handle, _tvb, _offset, len, 
             _reflection->GetString( *_message, field ).c_str() );
        break;
      default:
        proto_tree_add_item( _leaf, handles.handle, _tvb, _offset, len, true );
    };

    _offset+=len;

}

void kinetic_Dissector::dissectRepeatedField( const FieldDescriptor* field, int index )
{
    int len = 0;
    string scratch;

    if( !field->options().packed() )
    {
      len+= WireFormat::TagSize( field->number(), field->type() );
    }

    //DBG( "Dissecting field " << field->name() << " " << len );

    HandleMap::iterator it = handleMap->find( field->full_name() );

    if( it == handleMap->end() ) 
    {
      DBG_ERR( "Couldnt find handle for " << field->full_name() );
      return;
    }

    Handles handles = it->second;

    const EnumValueDescriptor* enumDesc = NULL;

    switch( field->cpp_type() )
    {
      case FieldDescriptor::CPPTYPE_UINT32:
        if( field->type() == FieldDescriptor::TYPE_FIXED32 )
        {
          len+= WireFormatLite::kFixed32Size;
        }
        else
        {
          len+= WireFormatLite::UInt32Size( _reflection->GetRepeatedUInt32( *_message, field, index )  );      
        }
        proto_tree_add_uint( _leaf, handles.handle, _tvb, _offset, len,  
           _reflection->GetRepeatedUInt32( *_message, field, index ) );
        break;
      case FieldDescriptor::CPPTYPE_INT32:
        if( field->type() == FieldDescriptor::TYPE_SFIXED32 )
        {
          len+= WireFormatLite::kSFixed32Size;
        }
        else if( field->type() == FieldDescriptor::TYPE_SINT32 )
        {
          len+= WireFormatLite::SInt32Size( _reflection->GetRepeatedInt32( *_message, field, index )  );  
        }
        else
        {
          len+= WireFormatLite::Int32Size( _reflection->GetRepeatedInt32( *_message, field, index )  ); 
        }
        proto_tree_add_int( _leaf, handles.handle, _tvb, _offset, len,  
          _reflection->GetRepeatedInt32( *_message, field, index ) );
        break;
      case FieldDescriptor::CPPTYPE_FLOAT:
        len+= WireFormatLite::kFloatSize;
        proto_tree_add_float( _leaf, handles.handle, _tvb, _offset, len,  
            _reflection->GetRepeatedFloat( *_message, field, index ) );
        break;
      case FieldDescriptor::CPPTYPE_UINT64:
        if( field->type() == FieldDescriptor::TYPE_FIXED64 )
        {
          len+= WireFormatLite::kFixed64Size;
        }
        else
        {
          len+= WireFormatLite::UInt64Size( _reflection->GetRepeatedUInt64( *_message, field, index )  ); 
        }
        proto_tree_add_uint64( _leaf, handles.handle, _tvb, _offset, len,  
             _reflection->GetRepeatedUInt64( *_message, field, index ) );
        break;
      case FieldDescriptor::CPPTYPE_INT64:
        if( field->type() == FieldDescriptor::TYPE_SFIXED64 )
        {
          len+= WireFormatLite::kSFixed64Size;
        }
        else if( field->type() == FieldDescriptor::TYPE_SINT64 )
        {
          len+= WireFormatLite::SInt64Size( _reflection->GetRepeatedInt64( *_message, field, index )  );  
        }
        else
        {
          len+= WireFormatLite::Int64Size( _reflection->GetRepeatedInt64( *_message, field, index )  ); 
        }
        proto_tree_add_int64( _leaf, handles.handle, _tvb, _offset, len,  
            _reflection->GetRepeatedInt64( *_message, field, index ) );
        break;
      case FieldDescriptor::CPPTYPE_DOUBLE:
        len+= WireFormatLite::kDoubleSize;
        proto_tree_add_double( _leaf, handles.handle, _tvb, _offset, len,  
             _reflection->GetRepeatedDouble( *_message, field, index ) );
        break;
      case FieldDescriptor::CPPTYPE_BOOL:
        len+= WireFormatLite::kBoolSize;
        proto_tree_add_boolean( _leaf, handles.handle, _tvb, _offset, len,
              _reflection->GetRepeatedBool( *_message, field, index ) );
        break;
      case FieldDescriptor::CPPTYPE_ENUM:
        enumDesc = _reflection->GetRepeatedEnum( *_message, field, index );
        len+= WireFormatLite::EnumSize( enumDesc->number() );
        proto_tree_add_int_format_value( _leaf, handles.handle, _tvb, _offset, len, 
                 enumDesc->number(), "%d ( %s )", enumDesc->number(),
                 enumDesc->name().c_str() );
        break;
      case FieldDescriptor::CPPTYPE_STRING:
        len+= WireFormatLite::StringSize( _reflection->GetRepeatedStringReference( *_message, field, index, &scratch ) );
        proto_tree_add_string( _leaf, handles.handle, _tvb, _offset, len,  
             _reflection->GetRepeatedString( *_message, field, index ).c_str() );
        break;
      default:
        proto_tree_add_item( _leaf, handles.handle, _tvb, _offset, len, true );
    };

    _offset+=len;

}


}
