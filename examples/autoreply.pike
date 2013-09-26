string url = "jabbers://jabber.org";

object jc;

int main(int argc, array argv)
{
  jc = Public.Protocols.Jabber.client(url);
  jc->set_user_identity("user@jabber.org");
  jc->begin();
  call_out(auth, 1);
  return -1;

}

void auth()
{
  jc->authenticate("user", "pass");
  call_out(msg, 1);
}

void msg()
{
  jc->set_presence_callback(got_presence);
  jc->set_presence(Public.Protocols.Jabber.PRESENCE_CHAT, "hello");
  jc->set_message_callback(got_msg);
  call_out(msg2, 1);
}

void msg2()
{
    jc->send_message("hey", "testing", "foo@jabber.org");
}

void got_presence(mapping p)
{
  werror("presence: %s\n", p->from);
}

void got_msg(mapping m)
{
  werror("got message: %s, %s\n", m->from, m->body||"");
  werror("sending reply.\n");
  jc->send_message(Calendar.now()->format_smtp() + " you said " + m->body||"", "re:" + m->body, m->from);
}


