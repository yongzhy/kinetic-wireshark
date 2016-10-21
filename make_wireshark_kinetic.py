#! /usr/bin/python
#
# Dilip Antony Joseph (dilip.antony.joseph at gmail.com)
# http://www.cs.berkeley.edu/~dilip/wireshark-protobuf
#
# NOTE FROM AUTHOR:
# This is my first Python program.  I am still learning the
# language.  If you find any glaring errors or coding style
# violations, please do email me.

import sys
import os
import re
import shutil

def read_config(config_file_name):
  cfg = {}
  infile = open(config_file_name, "r")
  for line in infile:
    if line == "" or line.isspace() or line.startswith("#") : continue
    p = line.split(':',1)
    cfg[p[0].strip()] = p[1].strip()
  infile.close()
  return cfg

# Main program starts here.

if len(sys.argv) != 2:
  print "Usage:", sys.argv[0], "PLUGIN_INFO_FILE"
  sys.exit(-1)

plugin_conf = read_config(sys.argv[1])

plugin_name = plugin_conf['name']

print 'Generating Wireshark plugin for ', plugin_name

wireshark_src_dir = plugin_conf['wireshark_src_dir']
wireshark_install_dir = plugin_conf['wireshark_install_dir']
wireshark_version = plugin_conf['wireshark_version']

plugin_dir = wireshark_src_dir + '/plugins/' + plugin_name

if os.path.exists(plugin_dir): shutil.rmtree(plugin_dir)

# Copy the plugin folder to destination
shutil.copytree(plugin_name, plugin_dir)

proto_files = plugin_conf['proto_file'].split()
proto_o_file_names = ''
for proto_file in proto_files:
  proto_o_file_names = proto_o_file_names + ' ' + os.path.splitext(os.path.basename(proto_file))[0] + '.pb.o'
main_proto_h_file_name = os.path.splitext(os.path.basename(proto_files[0]))[0] + '.pb.h'
proto_dir = os.path.dirname(proto_files[0])

glue_file_name = 'wireshark-glue-' + plugin_name + '.cc'
glue_o_file_name = os.path.splitext(glue_file_name)[0] + '.o'
glue_h_file_name = os.path.splitext(glue_file_name)[0] + '.h'
glue_h_define_name = glue_h_file_name.replace("-","_").replace(".","_")
plugin_so_file_name = '.libs/' + plugin_name + '.so'

curr_dir = os.getcwd()
os.chdir(wireshark_src_dir)
f=open("configure.ac","r")
text=f.read()
f.close()
p=re.compile("plugins/"+plugin_name+"/Makefile")

if p.search(text) == None:
  print "Adding plugins/"+plugin_name+"/Makefile to configure.ac"
  p=re.compile("\s+_CUSTOM_AC_OUTPUT_")
  modifiedText=p.sub("\n  plugins/"+plugin_name+"/Makefile\n  _CUSTOM_AC_OUTPUT_",text);
  f=open("configure.ac","w")
  f.write(modifiedText)
  f.close()
else:
  print "plugins/"+plugin_name+"/Makefile already present in configure.ac"

f=open("plugins/Makefile.am","r")
text=f.read()
f.close()

p=re.compile(plugin_name);
if p.search(text) == None:
   print "Adding "+plugin_name+" to plugins/Makefile.am"
   p=re.compile("wimaxasncp")
   modifiedText=p.sub("wimaxasncp \\\n        "+plugin_name,text);
   f=open("plugins/Makefile.am","w")
   f.write(modifiedText)
   f.close()
else:
   print plugin_name+" already present in plugins/Makefile.am"

os.system('./autogen.sh')
os.system('./configure --prefix=' + wireshark_install_dir + ' --with-plugins')
os.chdir(curr_dir)

# Compile the glue code
os.chdir(proto_dir)
if os.path.exists(glue_o_file_name): os.remove(glue_o_file_name)
os.system('c++ -fPIC -c ' + glue_file_name)
if not os.path.exists(glue_o_file_name):
  print "Unable to compile " + glue_file_name
  sys.exit(-1)
else:
  shutil.copy(proto_dir + '/' + glue_o_file_name, plugin_dir)

# Compile all the .o's for proto.pb.cc
for proto_file in proto_files:
  proto_o_file_name = os.path.splitext(os.path.basename(proto_file))[0] + '.pb.o'
  proto_c_file_name = os.path.splitext(os.path.basename(proto_file))[0] + '.pb.cc'
  if os.path.exists(proto_o_file_name): os.remove(proto_o_file_name)
  os.system('c++ -fPIC -c ' + proto_c_file_name)
  if not os.path.exists(proto_o_file_name):
    print "Unable to compile " + proto_c_file_name
    sys.exit(-1)
  else:
    shutil.copy(proto_dir + '/' + proto_o_file_name, plugin_dir)

os.chdir(curr_dir)

# Compile the plugin
os.chdir(plugin_dir)
if os.path.exists(plugin_so_file_name): os.remove(plugin_so_file_name)
os.system('make')
if not os.path.exists(plugin_so_file_name):
  print "Unable to compile wireshark plugin in " + plugin_dir
  sys.exit(-1)

# Copy the plugin so file to the wiresharks plugins directory.
if wireshark_install_dir != "" :
   shutil.copy(plugin_so_file_name, wireshark_install_dir + "/lib/wireshark/plugins/" + wireshark_version + "/")
