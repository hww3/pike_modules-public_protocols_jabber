//! a client for the Jabber protocol

import Public.Protocols.Jabber;

#define WERROR(X)
#ifdef JABBER_DEBUG
#define WERROR(X) werror("Jabber.client():" + X)
#endif

//! Context for SSL connections
SSL.context ssl_ctx;

string stream;
string url;
int sslcon=0;
string server;
int port;
string user,password;
string sessionid="";

mapping presence=([]);
mapping roster=([]);

private object conn;
private object messages=ADT.Queue();

private function message_callback;
private function subscribe_callback;
private function unsubscribe_callback;
private function subscribed_callback;
private function unsubscribed_callback;
private function presence_callback;
private function disconnect_callback;
private function roster_callback;

private string _client_name="PikeJabber";

//! sets the client name to be used in the connection to the Jabber server.
//! defaults to "PikeJabber".
void set_client_name(string c)
{
   if(stringp(c))
     _client_name=c;
}

//! returns the client name in use.
string get_client_name()
{
  return _client_name;
}

//! sets the function to be called when a session is disconnected.
//! 
//! the callback function does not receive any arguments.
void set_disconnect_callback(function f)
{
  if(functionp(f))
  {
     disconnect_callback=f;
  }
}

//! sets the function to be called when a user's precence info changes.
//! 
//! the callback function will receive a mapping containing the
//! contents of the presnece update
void set_presence_callback(function f)
{
  if(functionp(f))
  {
     presence_callback=f;
  }
}

//! sets the function to be called when the roster changes.
//! 
//! the callback function will receive a mapping containing the
//! contents of the roster change
void set_roster_callback(function f)
{
  if(functionp(f))
  {
     roster_callback=f;
  }
}


//! sets the function to be called when a message is received.
//! 
//! the callback function will receive a mapping containing the
//! contents of the message along with header information
void set_message_callback(function f)
{
  if(functionp(f))
  {
     message_callback=f;
  }
}

//! sets the function to be called when a subscribe request is received.
//! 
//! the callback function will receive a string containing the
//! Jabber ID making the request. the function should return a boolean
//! indicating whether the request should be accepted (true=accept)
void set_subscribe_callback(function f)
{
  if(functionp(f))
  {
     subscribe_callback=f;
  }
}

//! sets the function to be called when an unsubscribe request is received.
//! 
//! the callback function will receive a string containing the
//! Jabber ID making the request. the function should return a boolean
//! indicating whether the request should be accepted (true=accept)
void set_unsubscribe_callback(function f)
{
  if(functionp(f))
  {
     unsubscribe_callback=f;
  }
}

//! sets the function to be called when a subscribed notification is received.
//! 
//! the callback function will receive a string containing the
//! Jabber ID making the request.
void set_subscribed_callback(function f)
{
  if(functionp(f))
  {
     subscribed_callback=f;
  }
}

//! sets the function to be called when a unsubscribed notification is received.
//! 
//! the callback function will receive a string containing the
//! Jabber ID making the request.
void set_unsubscribed_callback(function f)
{
  if(functionp(f))
  {
     unsubscribed_callback=f;
  }
}

//! clears any disconnect callback
void clear_disconnect_callback()
{
   disconnect_callback=0;
}

//! clears any presence callback
void clear_presence_callback()
{
   presence_callback=0;
}


//! clears any roster callback
void clear_roster_callback()
{
   roster_callback=0;
}

//! clears any message callback
void clear_message_callback()
{
   message_callback=0;
}

//! clears any subscribe callback
void clear_subscribe_callback()
{
   subscribe_callback=0;
}

//! clears any unsubscribe callback
void clear_unsubscribe_callback()
{
   unsubscribe_callback=0;
}

//! clears any subscribed notification callback
void clear_subscribed_callback()
{
   subscribed_callback=0;
}

//! clears any unsubscribed notification callback
void clear_unsubscribed_callback()
{
   unsubscribed_callback=0;
}

//! returns an array of messages waiting to be received.
//! if a message callback is being used, delivery to the incoming message
//! queue is disabled, though any unreceived messages will be stored
//! for pickup later.
array get_messages()
{
  array m=({});
  while(!messages->is_empty())
    m+=({messages->get()});
  return m;
}

private array decode_url(string url) {
  string _prot,_server,_user,_password, tmp;
  int _port;
  int _use_ssl=0;
 
  int matches=0;

  WERROR("url: " + url + "\n");

  matches=sscanf(url, "%s://%s", _prot, _server);
 
  if(matches!=2) 
    error("jabber url " + url + " invalid.");

  if(_prot=="jabbers") _use_ssl=1;
  else if(_prot!="jabber") 
    error("unknown protocol " + _prot + ".");

  matches=sscanf(_server, "%s@%s", _user, tmp);

  if(matches==2)
  {
    sscanf(_user, "%s:%s", _user, _password);
    _server=tmp;
  }

  matches=sscanf(_server, "%s:%d", _server, _port);

  if(matches!=2)
  {
     if(_use_ssl==1)
       _port=5223;
     else _port=5222;
  }

  return ({_server, _port, _user, _password, _use_ssl});

}

//! create a new client connection to server url, using a jabber url
//! @param ctx
//!   an optional context for an SSL connection to the Jabber server.  
//!
//! @example
//!  jabber://user:pass@@jabberserver.fqdn
void create(string url, void|SSL.context ctx)
{
  string _server,_user,_password;
  int _ssl,_port;
  [_server, _port, _user, _password, _ssl]=decode_url(url);

    conn=Stdio.File();
    if(!conn->connect(_server, _port))
      error("unable to connect to jabber server at " + _server + " port " + 
      _port + ".");

  if(_ssl) // are we using ssl?
  {
    object _c;
    _c = conn;

    if(!ctx)
      ctx = SSL.context();

    ssl_ctx = ctx;

    conn = SSL.sslfile(_c, ctx, 1, 0);
    sslcon = 1;
  }

  conn->set_close_callback(conn_closed);

  user=_user;
  port=_port;
  server=_server;
  password=_password;

  get_new_session();

  set_background_mode(1);
}

private void conn_closed()
{
  if(disconnect_callback)
    call_function(disconnect_callback);
}

private string make_stream(string s)
{
   return stream + s + "</stream:stream>\n";
}

private int|string check_for_autherrors(string s)
{
  object node;
  mixed e;

  node=Parser.XML.NSTree->parse_input(s);
  _auth_error=0;
  
  if(node->walk_inorder(low_checkforautherrors)==Parser.XML.NSTree.STOP_WALK 
    && _auth_error==1)
      return _error;
  _auth_error=0;
  return 0;  
  
}

private object|string check_for_errors(string s)
{
  object node;
  mixed e;
  e=catch(node=Parser.XML.NSTree->parse_input(make_stream(s)));
  if(e)
  {
    WERROR("found error.\n");
    node=Parser.XML.NSTree->parse_input(stream + s);
    if(node->walk_inorder(low_checkforerrors)==Parser.XML.NSTree.STOP_WALK)
      return _error;
  }


  // what's the first tag?
  foreach(node->get_children(), object n)
    if(n->get_tag_name()=="stream")
      if(n[0]->get_tag_name()=="error")
      {
         return n[0]->get_children()[0]->get_text();
      }

  return node;  
  
}

private string _error;

private void|int low_checkforerrors(object node)
{
  if(node->get_tag_name()=="error")
  {
    _error=node->value_of_node();
    return Parser.XML.NSTree.STOP_WALK; 
  }
}

private int _auth_error;

private void|int low_checkforautherrors(object node)
{
  if(node->get_tag_name()=="iq" && node->get_attributes()->type!="error")
  {
    return Parser.XML.NSTree.STOP_WALK;
  }

  if(node->get_tag_name()=="error")
  {
    _error=node->value_of_node();
    _auth_error=1;
    return Parser.XML.NSTree.STOP_WALK; 
  }
}

//! send message m with subject s to user u
int send_message(string m, string s, string u)
{
  string msg="<message to='" + u + "' "
     // "from='" + user + "@" + server + "/" 
     //     + _client_name + "'"
      ">\n"
     "<subject>" + s + "</subject>\n"
     "<body>" + m + "</body>\n"
     "</message>";

  send_msg(msg);
  return 1;
}

//!
int respond_subscribed(string who)
{ 
  string msg="";

  msg+="<presence to='" + who + "' type='subscribed'/>";
  
  send_msg(msg);
}

//!
int respond_unsubscribed(string who)
{ 
  string msg="";

  msg+="<presence to='" + who + "' type='unsubscribed'/>";
  
  send_msg(msg);
}

//!
int request_roster()
{
  string msg="";

  msg+="<iq type='get' id='roster_1'><query xmlns='jabber:iq:roster'/></iq>";

  send_msg(msg);
}

//!
int request_remove(string who)
{
  string msg="";

  msg+="<iq type='set' id='remove1'><query xmlns='jabber:iq:roster'>"
    "<item jid='" + who  + "' subscription='remove'/></query></iq>";

  send_msg(msg);
}

//!
int request_subscribe(string who, string nick, string roster)
{
  string msg="";

  msg+="<iq type='set'><query xmlns='jabber:iq:roster'>";
  msg+="<item jid='" + who + "' name='" + nick +"'>";
  msg+="<group>" + roster + "</group>";
  msg+="</item>";
  msg+="</query></iq>";
  msg+="<presence to='" + who + "' type='subscribe'/>";

  send_msg(msg);
}


int request_unsubscribe(string who)
{
  string msg="";

  msg+="<presence type='unsubscribe' to='" + who + "' />";

  send_msg(msg);
}

//! set presence of the logged in user
//! @param show
//!   should be one of @[PRESENCE_AWAY],
//!   @[PRESENCE_CHAT], @[PRESENCE_DND] or @[PRESENCE_XA].
//! @param status
//!   an optional string containing a status message
//! @param priority
//!   an optional priority setting (see Jabber spec for details)
//! @note
//!   we don't use the cdata in the text because some clients
//!   don't know what to do with that. we should probably complain,
//!   as it's perfectly valid xml.
int set_presence(int show, string|void status, int|void priority)
{
  string msg="";
  msg="<presence>";

  if(show==PRESENCE_UNAVAILABLE)
    msg="<presence type='unavailable'>";
  else if(show==PRESENCE_AWAY)
    msg+="<show>away</show>";
  else if(show==PRESENCE_CHAT)
    msg+="<show>chat</show>";
  else if(show==PRESENCE_DND)
    msg+="<show>dnd</show>";
  else if(show==PRESENCE_XA)
    msg+="<show>xa</show>";
 
  if(status)
    msg+="<status>" + status + "</status>";

  msg+="<priority>" + (priority||5) + "</priority>";  
  msg+="</presence>\n";

  send_msg(msg);
  return 1;
}

//! right now we only do plaintext authentication.
//! will use user/password information gleaned from the jabber url if
//! authentication information is not provided.
void authenticate(string|void u, string|void p)
{

  set_background_mode(0);

  if(!(u && p)) // we should use the gleaned information.
  {
     u=user;
     p=password;
  }

  string msg="<iq id='auth1' type='get'>\n"
      "    <query xmlns='jabber:iq:auth'>\n"
      "      <username>" + u + "</username>\n"
      "    </query>\n"
      "  </iq>";

  send_msg(msg);

  string rslt=conn->read(2048,1);

  WERROR(rslt+"\n\n");
  mixed e=check_for_errors(rslt);
  if(stringp(e))
    error("Received error: " + e + "\n");
  object node=e;
//  object node=Parser.XML.NSTree->parse_input(make_stream(rslt));

  WERROR(Parser.XML.NSTree->visualize(node));

  msg="<iq id='auth2' type='set'>"
   "<query xmlns='jabber:iq:auth'>"
   " <username>" + u + "</username>"
   " <password>" + p + "</password>"
   " <resource>" + _client_name + "</resource>"
   "</query>"
   "</iq>";

  send_msg(msg);

  rslt=conn->read(2048,1);
  WERROR(rslt+"\n\n");

  catch(e=check_for_autherrors(rslt));
  if(e)
    error("Received error: " + e + "\n");

  set_background_mode(0);

}

//!
void disconnect()
{
   string msg="</stream:stream>\n";
   send_msg(msg);
   conn->close();
   this->destroy();
}

//!
void get_new_session()
{
  string msg="<stream:stream\n"
             "  to='" + server + "'\n"
             "  xmlns='jabber:client'\n"
             "  xmlns:stream='http://etherx.jabber.org/streams'>\n";  
  send_msg(msg);

  string rslt=conn->read(2048,1);
  object node=Parser.XML.NSTree->parse_input(rslt + "</stream:stream>");
  parse_stream(node);
  stream=rslt;
  return;
}

private int low_parse_stream(object n)
{
  if(n->get_tag_name()=="stream")
  {
    mapping a=n->get_attributes();
    if(!a->id)     return !Parser.XML.NSTree.STOP_WALK;  
    sessionid=a->id;
    return Parser.XML.NSTree.STOP_WALK;  
  }
}

private void parse_stream(object n)
{
  if(n->iterate_children(low_parse_stream) !=Parser.XML.NSTree.STOP_WALK) 
    error("Invalid stream received from server.\n");
}


//!
void set_background_mode(int i)
{
   if(i)
   {
      conn->set_nonblocking();
      conn->set_read_callback(low_read_message);
   }
   else
   {
      conn->set_blocking();
   }

}

private void low_read_message(int id, string data)
{
  WERROR("received *>>" + data + "<<*\n");
  mixed e=check_for_errors(data);
  if(stringp(e))
    error("Received error: " + e + "\n");
  object node=e;

  //
  // NOTE: we _assume_ that node is the stream container element
  // and that node[0] is the first element. we probably shouldn't do that.
  //
  node[0]->iterate_children(low_low_read_message);

}

private int low_low_read_message(object node)
{
   string type=node->get_tag_name();

WERROR("got " + type +"\n");
   if(type=="message") // we have a message incoming to us.
   {
      mapping msg=([]);
      msg->timestamp=time();
      msg+=node->get_attributes();
      foreach(node->get_children(), object n)
         low_parse_message(n, msg);

      if(message_callback)
        call_function(message_callback, msg);
      else
        messages->put(msg);

//      return Parser.XML.NSTree.STOP_WALK;
   }
   else if(type=="presence") // we have a presence update.
   {
      mapping a=node->get_attributes();
      if(!a->type) a->type="available";

      foreach(node->get_children(), object n)
         low_parse_presence(n, a);
      if(a->type && a->type=="subscribe")
         handle_subscribe(a->from);
      else if(a->type && a->type=="unsubscribe")
         handle_unsubscribe(a->from);
      else if(a->type && a->type=="subscribed")
         handle_subscribed(a->from);
      else if(a->type && a->type=="unsubscribed")
         handle_unsubscribed(a->from);
          
       WERROR("got presence data from " + sprintf("%O", a) + "\n");
       presence[a->from]=a;
       string bn=((a->from)/"/")[0];
       if(presence_callback)
         call_function(presence_callback, a);
      if(a->type && a->type=="unavailable" && roster[bn])
         roster[bn]->clients-=({a->from});
       else if(roster[bn]) 
          roster[bn]->clients=Array.uniq(roster[bn]->clients + ({a->from}));
   }
   else if(type=="iq") // we have an iq
   {
      mapping a=node->get_attributes();
      low_parse_iq(node, a);
      WERROR("got iq data from " + sprintf("%O", a) + "\n");
  
   }
   else 
   {
      WERROR("unknown data from server: " + node->render_xml() +"\n");
   }
}

private int low_parse_message(object node, mapping msg)
{
    if(node->get_tag_name()=="html")
    {
      msg["html"]=(string)node;
      return 0;
    }
    if(node->get_node_type()==Parser.XML.Tree.XML_TEXT)
      return 0;
    if(node->get_node_type()==Parser.XML.Tree.XML_ELEMENT)
    msg[node->get_tag_name()]=node->value_of_node();

    return 1;
}

private int low_parse_presence(object node, mapping a)
{  
    if(node[0])
      a[node->get_tag_name()]=node[0]->get_text();
}

private int low_parse_iq(object node, mapping a)
{

    if(a->type=="result")
    {
       WERROR("received a result for request " + a->id + "\n");
    }
    if(node[0] && node[0]->get_tag_name()=="query")
    {
       WERROR("got a query\n");
       switch(node[0]->get_ns())
       {
         case "jabber:iq:roster":
           if(a->type=="set")
           {
             WERROR("working with a set roster query\n");
             foreach(node[0]->get_children(), object i)
             {
               if(i->get_tag_name()=="item")
               {
                 mapping ent=i->get_attributes();

                 if(!roster[ent->jid])
                   roster[ent->jid]=([]);
                 roster[ent->jid]->name=(ent->name||"");
                 roster[ent->jid]->subscription=(ent->subscription||"");
                 foreach(i->get_children(), object gp)
                   if(gp->get_tag_name()=="group")
                     roster[ent->jid]->group=gp[0]->get_text();
		if(!roster[ent->jid]->clients)
                   roster[ent->jid]->clients=({});
                if(roster_callback)
                  call_function(roster_callback, roster);
               }
             }
           }
         break;
         default:
           WERROR("unknown iq query type " + node[0]->get_ns() + ".\n");
         break;
       }
    }
    return 1;
}


private void handle_unsubscribe(string who)
{
  int res;
  if(unsubscribe_callback)
    res=unsubscribe_callback(who);
  if(res)
    respond_unsubscribed(who);
  else
    respond_subscribed(who);
}

private void handle_subscribe(string who)
{
  int res;
  if(subscribe_callback)
    res=subscribe_callback(who);
  if(res)
    respond_subscribed(who);
  else
    respond_unsubscribed(who);
}

private void handle_unsubscribed(string who)
{
  if(unsubscribed_callback)
    unsubscribed_callback(who);

  // acknowledge

  string msg="";
  msg+="<presence type='unsubscribe' to='" + who + "'/>";

  send_msg(msg);
  WERROR("acknowledged subscription.\n");
}

private void handle_subscribed(string who)
{
  if(subscribed_callback)
    subscribed_callback(who);

  // acknowledge

  string msg="";
  msg+="<presence type='subscribe' to='" + who + "'/>";

  send_msg(msg);
  WERROR("acknowledged subscription.\n");
}

private void send_msg(string msg)
{
  conn->write(msg);
  WERROR("sent : " + msg + "\n\n");
}
