/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_force.c - force joins a user
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 */

#include "stdinc.h"
#include "client.h"
#include "hash.h"		/* for find_client() */
#include "ircd.h"
#include "numeric.h"
#include "logger.h"
#include "s_serv.h"
#include "s_conf.h"
#include "send.h"
#include "whowas.h"
#include "match.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "s_newconf.h"

static int ms_forcejoin(struct Client *, struct Client *, int, const char **);
static int mo_forcejoin(struct Client *, struct Client *, int, const char **);

static void user_join_override(struct Client *, struct Client *, struct Client *, const char *);


struct Message forcejoin_msgtab = {
	"FORCEJOIN", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_not_oper, {ms_forcejoin, 2}, {ms_forcejoin, 2}, mg_ignore, {mo_forcejoin, 2}}
};

mapi_clist_av1 forcejoin_clist[] = { &forcejoin_msgtab, NULL };

DECLARE_MODULE_AV1(forcejoin, NULL, NULL, forcejoin_clist, NULL, NULL, "Shadowircd development team");

/*
** mo_forcejoin
**      parv[1] = forcejoin victim
**      parv[2] = forcejoin channel list
*/
static int
mo_forcejoin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	const char *user, *chanlist;

	user = parv[1];

	if(!IsOperAdmin(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "admin");
		return 0;
	}

	if(EmptyString(parv[2]))
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS), me.name, source_p->name, "FORCEJOIN");
		return 0;
	}
	else
		chanlist = parv[2];

	if((target_p = find_named_person(user)) == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHNICK, form_str(ERR_NOSUCHNICK), user);
		return 0;
	}
	
	if(!IsPerson(target_p))
		return 0;

	sendto_wallops_flags(UMODE_WALLOP, &me,
			     "FORCEJOIN called for [%s] by %s!%s@%s",
			     parv[1], source_p->name, source_p->username, source_p->host);
	ilog(L_MAIN, "FORCEJOIN called for [%s] by %s!%s@%s",
	     parv[1], source_p->name, source_p->username, source_p->host);

	if(!MyClient(target_p))
	{
		struct Client *cptr = target_p->servptr;
		sendto_one(cptr, ":%s FORCEJOIN %s :%s", 
				 get_id(source_p, cptr), get_id(target_p, cptr), chanlist);
		return 0;
	}
	else
	{
		sendto_one_notice(source_p, ":You have been forcejoined to %s by %s",
				  chanlist, source_p->name);
		user_join_override(client_p, source_p, target_p, chanlist);
	}

	return 0;
}

/*
 * ms_forcejoin
 *      parv[1] = forcejoin victim
 *      parv[2] = forcejoin channel list 
 */
static int
ms_forcejoin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	const char *user, *chanlist;

	user = parv[1];
	
	if(EmptyString(parv[2]))
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS), me.name, source_p->name, "FORCEJOIN");
		return 0;
	}
	else
		chanlist = parv[2];

	/* Find the user */
	if((target_p = find_person(user)) == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHNICK, form_str(ERR_NOSUCHNICK), user);
		return 0;
	}

	if(IsServer(target_p) || IsMe(target_p))
	{
		sendto_one_numeric(source_p, ERR_NOSUCHNICK, form_str(ERR_NOSUCHNICK), user);
		return 0;
	}

	ilog(L_MAIN, "FORCEJOIN called for [%s] by %s!%s@%s",
	     parv[1], source_p->name, source_p->username, source_p->host);
	
	if(!MyClient(target_p))
	{
		struct Client *cptr = target_p->servptr;
		sendto_one(cptr, ":%s FORCEJOIN %s :%s", 
				 get_id(source_p, cptr), get_id(target_p, cptr), chanlist);
		return 0;
	}

	user_join_override(client_p, source_p, target_p, chanlist);

	return 0;
}

/* Join a channel, ignoring forwards, +ib, etc. It notifes source_p of any errors joining
 * NB: this assumes a local user.
 */
void user_join_override(struct Client * client_p, struct Client * source_p, struct Client * target_p, const char * channels)
{
	static char jbuf[BUFSIZE];
	struct Channel *chptr = NULL;
	char *name;
	const char *modes;
	char *p = NULL;
	char *chanlist;

	jbuf[0] = '\0';

	if(channels == NULL)
		return;

	/* rebuild the list of channels theyre supposed to be joining.
	 * this code has a side effect of losing keys, but..
	 */
	chanlist = LOCAL_COPY(channels);
	for(name = rb_strtok_r(chanlist, ",", &p); name; name = rb_strtok_r(NULL, ",", &p))
	{
		/* check the length and name of channel is ok */
		if(!check_channel_name_loc(target_p, name) || (strlen(name) > LOC_CHANNELLEN))
		{
			sendto_one_numeric(source_p, ERR_BADCHANNAME,
					   form_str(ERR_BADCHANNAME), (unsigned char *) name);
			continue;
		}

		/* join 0 parts all channels */
		if(*name == '0' && (name[1] == ',' || name[1] == '\0') && name == chanlist)
		{
			(void) strcpy(jbuf, "0");
			continue;
		}

		/* check it begins with # or &, and local chans are disabled */
				else if(!IsChannelName(name) ||
						( !ConfigChannel.use_local_channels && name[0] == '&'))
		{
			sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
					   form_str(ERR_NOSUCHCHANNEL), name);
			continue;
		}

		if(*jbuf)
			(void) strcat(jbuf, ",");
		(void) rb_strlcat(jbuf, name, sizeof(jbuf));
	}

	for(name = rb_strtok_r(jbuf, ",", &p); name; name = rb_strtok_r(NULL, ",", &p))
	{
		/* JOIN 0 simply parts all channels the user is in */
		if(*name == '0' && !atoi(name))
		{
			if(target_p->user->channel.head == NULL)
				continue;

			do_join_0(&me, target_p);
			continue;
		}
		
		if((chptr = find_channel(name)) != NULL)
		{
			if(IsMember(target_p, chptr))
			{
			/* debugging is fun... */
				sendto_one_notice(source_p, ":*** Notice -- %s is already in %s",
					 target_p->name, chptr->chname);
				return;
			}

			add_user_to_channel(chptr, target_p, CHFL_PEON);

			sendto_server(target_p, chptr, NOCAPS, NOCAPS,
			      ":%s JOIN %ld %s +",
			      target_p->id, (long) chptr->channelts,
			      chptr->chname);

			sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
					     target_p->name, target_p->username,
					     target_p->host, chptr->chname);

			del_invite(chptr, target_p);

			if(chptr->topic != NULL)
			{
				sendto_one(target_p, form_str(RPL_TOPIC), me.name,
				   target_p->name, chptr->chname, chptr->topic);
				sendto_one(target_p, form_str(RPL_TOPICWHOTIME),
					   me.name, source_p->name, chptr->chname,
					   chptr->topic_info, chptr->topic_time);
			}

			channel_member_names(chptr, target_p, 1);
		}
		else
		{
			if(!check_channel_name(name))
			{
				sendto_one(source_p, form_str(ERR_BADCHANNAME), me.name,
					   source_p->name, (unsigned char *) name);
				return;
			}

			/* channel name must begin with & or # */
			if(!IsChannelName(name))
			{
				sendto_one(source_p, form_str(ERR_BADCHANNAME), me.name,
					   source_p->name, (unsigned char *) name);
				return;
			}

			/* name can't be longer than CHANNELLEN */
			if(strlen(name) > CHANNELLEN)
			{
				sendto_one_notice(source_p, ":Channel name is too long");
				return;
			}

			chptr = get_or_create_channel(target_p, name, NULL);
			add_user_to_channel(chptr, target_p, CHFL_CHANOP);
			
			/* send out a join, make target_p join chptr */
			sendto_server(target_p, chptr, NOCAPS, NOCAPS,
				      ":%s SJOIN %ld %s +nt :@%s", me.id,
				      (long) chptr->channelts, chptr->chname, target_p->id);

			sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
					     target_p->name, target_p->username,
					     target_p->host, chptr->chname);
		
			/* autochanmodes stuff */
			if(ConfigChannel.autochanmodes)
			{
				char * ch;
				for(ch = ConfigChannel.autochanmodes; *ch != '\0'; ch++)
				{
					chptr->mode.mode |= chmode_table[(unsigned int)*ch].mode_type;
				}
			}
			else
			{
				chptr->mode.mode |= MODE_TOPICLIMIT;
				chptr->mode.mode |= MODE_NOPRIVMSGS;
			}

			modes = channel_modes(chptr, &me);
			sendto_channel_local(ALL_MEMBERS, chptr, ":%s MODE %s %s",
					     me.name, chptr->chname, modes);

			target_p->localClient->last_join_time = rb_current_time();
			channel_member_names(chptr, target_p, 1);

			/* we do this to let the oper know that a channel was created, this will be
			 * seen from the server handling the command instead of the server that
			 * the oper is on.
			 */
			sendto_one_notice(source_p, ":*** Notice -- Creating channel %s", chptr->chname);
		}
	}		


	return;
}
