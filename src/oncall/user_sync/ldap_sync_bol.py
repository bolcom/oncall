from gevent import monkey, sleep, spawn
monkey.patch_all()  # NOQA

import sys
import time
import yaml
import logging
import ldap
import yaml

from oncall import metrics
from ldap.controls import SimplePagedResultsControl
from datetime import datetime
from pytz import timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from phonenumbers import format_number, parse, PhoneNumberFormat
from phonenumbers.phonenumberutil import NumberParseException


logger = logging.getLogger()
formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)
logger.setLevel(logging.INFO)
logger.addHandler(ch)

stats = {
    'ldap_found': 0,
    'sql_errors': 0,
    'teams_added': 0,
    'team_admins_failed_to_add': 0,
    'team_admins_failed_to_remove': 0,
    'team_user_failed_to_add': 0,
    'team_user_failed_to_remove': 0,
    'roster_user_failed_to_add': 0,
    'roster_user_failed_to_remove': 0,
    'roster_failed_to_add': 0,
    'roster_failed_to_remove': 0,
    'schedule_failed_to_add': 0,
    'schedule_failed_to_remove': 0,
    'teams_failed_to_add': 0,
    'teams_failed_to_update': 0,
    'teams_failed_to_deactivate': 0,
    'teams_deactivated': 0,
    'users_added': 0,
    'users_failed_to_add': 0,
    'users_failed_to_update': 0,
    'users_purged': 0,
    'user_contacts_updated': 0,
    'user_names_updated': 0,
    'user_photos_updated': 0,
    'users_reactivated': 0,
    'users_failed_to_reactivate': 0,
}

LDAP_SETTINGS = {}
SCRUMTEAMS = {}
STANDBYTEAMS = {}
STANDBYESCALATIONTEAMS = {}


def normalize_phone_number(num):
    return format_number(parse(num.decode('utf-8'), 'US'), PhoneNumberFormat.INTERNATIONAL)


def get_predefined_users(config):
    users = {}

    try:
        config_users = config['sync_script']['preset_users']
    except KeyError:
        return {}

    for user in config_users:
        users[user['name']] = user
        for key in ['sms', 'call']:
            try:
                users[user['name']][key] = normalize_phone_number(users[user['name']][key])
            except (NumberParseException, KeyError, AttributeError):
                users[user['name']][key] = None

    return users


def timestamp_to_human_str(timestamp, tz):
    dt = datetime.fromtimestamp(timestamp, timezone(tz))
    return ' '.join([dt.strftime('%Y-%m-%d %H:%M:%S'), tz])


def prune_user(engine, username):
    global stats
    stats['users_purged'] += 1

    try:
        engine.execute('DELETE FROM `user` WHERE `name` = %s', username)
        logger.info('Set user %s to inactive', username)

    # The user has messages or some other user data which should be preserved.
    # Just mark as inactive.
    except IntegrityError:
        logger.info('Marking user %s inactive', username)
        engine.execute('UPDATE `user` SET `active` = FALSE WHERE `name` = %s', username)

    except SQLAlchemyError as err:
        logger.error('Deleting user %s failed: %s', username, err)
        stats['sql_errors'] += 1

def fetch_ldap():
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
    l = ldap.initialize(LDAP_SETTINGS['url'])
    l.set_option(ldap.OPT_X_TLS_CACERTFILE, LDAP_SETTINGS['cert_path'])
    l.simple_bind_s(LDAP_SETTINGS['user'], LDAP_SETTINGS['password'])

    req_ctrl = SimplePagedResultsControl(True, size=1000, cookie='')

    known_ldap_resp_ctrls = {
        SimplePagedResultsControl.controlType: SimplePagedResultsControl,
    }

    base = LDAP_SETTINGS['base']
    attrs = ['distinguishedName'] + LDAP_SETTINGS['attrs'].values()
    query = LDAP_SETTINGS['query']

    users = {}
    dn_map = {}

    while True:
        msgid = l.search_ext(base, ldap.SCOPE_SUBTREE, query, attrs, serverctrls=[req_ctrl])
        rtype, rdata, rmsgid, serverctrls = l.result3(msgid, resp_ctrl_classes=known_ldap_resp_ctrls)
        logger.info('Loaded %d user entries from ldap.' % len(rdata))
        for dn, ldap_dict in rdata:
            if LDAP_SETTINGS['attrs']['mail'] not in ldap_dict:
                logger.error('ERROR: invalid ldap entry for dn: %s' % dn)
                continue

            try:
                username_field = LDAP_SETTINGS['attrs']['username']
            except KeyError:
                username_field = "sAMAccountName"

            username = ldap_dict[username_field][0]

            mobile = ldap_dict.get(LDAP_SETTINGS['attrs']['mobile'])
            mail = ldap_dict.get(LDAP_SETTINGS['attrs']['mail'])
            name = ldap_dict.get(LDAP_SETTINGS['attrs']['full_name'])[0]

            if mobile:
                try:
                    mobile = normalize_phone_number(mobile[0])
                except NumberParseException:
                    mobile = None
                except UnicodeEncodeError:
                    mobile = None

            if mail:
                mail = mail[0]
                slack = mail.split('@')[0]
            else:
                slack = None

            # TODO: we'd definitely like to do something smarter here
            hipchat = name.replace(' ', '')
            contacts = {'call': mobile, 'sms': mobile, 'email': mail, 'slack': slack, 'name': name, 'hipchat': hipchat}
            dn_map[dn] = username
            users[username] = contacts

        pctrls = [
            c for c in serverctrls if c.controlType == SimplePagedResultsControl.controlType
        ]

        cookie = pctrls[0].cookie
        if not cookie:
            break
        req_ctrl.cookie = cookie

    return users, dn_map


# given all ldap users, return an oncall team with contact details and members
def process_ldap_team_gon(users, dn, ldap_con, ldap_dict):
    if LDAP_SETTINGS['team_attrs']['members'] not in ldap_dict:
        logger.error('ERROR: invalid ldap entry for dn: %s', dn)
        return None

    try:
        teamname_field = LDAP_SETTINGS['team_attrs']['name']
    except KeyError:
        logger.error("Couldn't find name field for dn: %s", dn)

    teamname = ldap_dict[teamname_field][0].replace('-gon', '')

    member_uids = []
    team = {}
    for member in ldap_dict.get(LDAP_SETTINGS['team_attrs']['members']):
        if member in LDAP_SETTINGS['member_blacklist']:
            continue
        if member in users:
            try:
                rdata = ldap_con.search_s(member, ldap.SCOPE_BASE, '(objectClass=*)', attrlist=['uid'])
                member_uids.append(rdata[0][1]['uid'][0])
            except ldap.NO_SUCH_OBJECT:
                logger.info("Team %s has a non-existant member: %s", teamname, member)
    teamphone = ldap_dict.get(LDAP_SETTINGS['team_attrs']['phonenumber'])
    team["ad-" + teamname] = {'members': member_uids, 'phonenumber': teamphone}

    return team


def get_ldap_teams(users):
    teams = {}

    # bind ldap
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
    ldap_con = ldap.initialize(LDAP_SETTINGS['url'])
    ldap_con.set_option(ldap.OPT_X_TLS_CACERTFILE, LDAP_SETTINGS['cert_path'])
    ldap_con.simple_bind_s(LDAP_SETTINGS['user'], LDAP_SETTINGS['password'])

    # query and process scrumteams
    base = LDAP_SETTINGS['team_base']
    attrs = ['distinguishedName'] + LDAP_SETTINGS['team_attrs'].values()
    query = LDAP_SETTINGS['team_query']

    msgid = ldap_con.search_ext(base, ldap.SCOPE_SUBTREE, query, attrs)
    rtype, rdata, rmsgid, serverctrls = ldap_con.result3(msgid)
    logger.info('Loaded %d scrum team entries from ldap.', len(rdata))

    for dn, ldap_dict in rdata:
        team = process_ldap_team_gon(users, dn, ldap_con, ldap_dict)
        if team:
            teams.update(team)

    # process team_additional_groups
    attrs = ['distinguishedName'] + LDAP_SETTINGS['team_attrs'].values()
    query = LDAP_SETTINGS['team_query']

    for team_dn in LDAP_SETTINGS['team_additional_groups']:
        rdata = ldap_con.search_s(team_dn, ldap.SCOPE_BASE, query)
        for dn, ldap_dict in rdata:
            team = process_ldap_team_gon(users, dn, ldap_con, ldap_dict)
            if team:
                teams.update(team)

    return teams


# Take a team name and list of members in the form of uid's
# Change team_admin and team_user tables to reflect ldap teams
def set_team_admins(engine, teamname, members):
    team_id = get_team_id(engine, teamname)
    team_admins_query = 'SELECT `user_id`, `team_id` FROM `team_admin` WHERE `team_id`='+str(team_id)

    team_admin_ids = []
    for row in engine.execute(team_admins_query):
        team_admin_ids.append(row.user_id)

    team_member_ids = []
    team_member_id_map = {}
    for member in members:
        user_id = get_user_id(engine, member)
        if user_id:
            team_member_id_map[user_id] = member
            team_member_ids.append(user_id)
        else:
            logger.info("When setting admins for %s, could not find %s id", teamname, member)

    team_admins_to_remove = set(team_admin_ids) - set(team_member_ids)
    for exadmin in team_admins_to_remove:
        logger.info("Removing %s from team %s admins and users", exadmin, teamname)
        delete_team_admin(engine, team_id, exadmin)
        delete_team_user(engine, team_id, exadmin)

    team_admins_to_add = set(team_member_ids) - set(team_admin_ids)
    for admin in team_admins_to_add:
        logger.info("Adding %s to team %s's admins and users", team_member_id_map[admin], teamname)
        insert_team_admin(engine, team_id, admin)
        insert_team_user(engine, team_id, admin)


def get_team_id(engine, team):
    team_id = engine.execute('SELECT `id`, `name` FROM `team` WHERE `name`="'+team+'"').fetchone()['id']
    return team_id


def get_team_name(engine, team_id):
    team = engine.execute('SELECT `id`, `name` FROM `team` WHERE `id`="'+str(team_id)+'"').fetchone()['name']
    return team


def get_user_id(engine, user):
    try:
        user_id = engine.execute('SELECT `id`, `name` FROM `user` WHERE `name`="'+user+'"').fetchone()['id']
    except TypeError:
        return None

    return user_id


def get_user_name(engine, user_id):
    try:
        user = engine.execute('SELECT `id`, `name` FROM `user` WHERE `id`='+user+'').fetchone()['name']
    except TypeError:
        logger.exception("Unable to get user for id %s", user_id)
        raise
    return user


def delete_team_admin(engine, team_id, user_id):
    try:
        engine.execute("DELETE FROM team_admin WHERE user_id ="+str(user_id)+" AND team_id="+str(team_id))
    except SQLAlchemyError:
        stats['teams_admins_failed_to_remove'] += 1
        stats['sql_errors'] += 1
        logger.exception('Failed to delete team admin %s from team %s', get_user_name(user_id), get_team_name(team_id))
        raise


def delete_team_user(engine, team_id, user_id):
    try:
        engine.execute("DELETE FROM team_user WHERE user_id ="+str(user_id)+" AND team_id="+str(team_id))
    except SQLAlchemyError:
        stats['teams_user_failed_to_remove'] += 1
        stats['sql_errors'] += 1
        logger.exception('Failed to delete team user %s from team %s', get_user_name(user_id), get_team_name(team_id))
        raise


def insert_team_admin(engine, team_id, user_id):
    try:
        engine.execute('INSERT INTO team_admin VALUES('+str(team_id)+','+str(user_id)+')')
    except SQLAlchemyError:
        stats['teams_admins_failed_to_add'] += 1
        stats['sql_errors'] += 1
        logger.exception('Failed to add team admin %s to team %s',
                         get_user_name(engine, user_id),
                         get_team_name(engine, team_id))
        raise


def insert_team_user(engine, team_id, user_id):
    try:
        engine.execute('INSERT INTO team_user VALUES('+str(team_id)+','+str(user_id)+')')
    except SQLAlchemyError:
        stats['team_user_failed_to_add'] += 1
        stats['sql_errors'] += 1
        logger.exception('Failed to add team user %s to team %s', get_user_name(engine, user_id), get_team_name(engine, team_id))
        raise


def get_roster(engine, name):
    roster_id = None
    try:
        roster_id = engine.execute('SELECT `id`, `name` FROM roster WHERE name="'+name+'"').fetchone()['id']
    except SQLAlchemyError:
        logger.exception('Failed to find roster %s', name)
        raise
    except TypeError:
        pass
    return roster_id


def insert_roster(engine, name, team_id):
    try:
        roster_id = engine.execute('INSERT INTO roster VALUES(NULL,"'+str(name)+'",'+str(team_id)+')').lastrowid
    except SQLAlchemyError:
        stats['roster_failed_to_add'] += 1
        stats['sql_errors'] += 1
        logger.exception('Failed to add roster %s', name)
        raise
    return roster_id


def delete_roster(engine, name, team_id):
    try:
        engine.execute('DELETE FROM roster WHERE name="'+str(name)+'" AND team_id='+str(team_id)+')')
    except SQLAlchemyError:
        stats['roster_failed_to_remove'] += 1
        stats['sql_errors'] += 1
        logger.exception('Failed to remove roster %s', name)
        raise


def insert_roster_user(engine, roster_id, user_id, in_rotation, roster_priority):
    try:
        engine.execute('INSERT INTO roster_user VALUES('+str(roster_id)+','+str(user_id)+','+str(in_rotation)+','+str(roster_priority)+')')
    except SQLAlchemyError:
        stats['roster_user_failed_to_add'] += 1
        stats['sql_errors'] += 1
        logger.exception('Failed to add roster user %s to team %s', user_id, roster_id)
        raise


def delete_roster_user(engine, team_id, user_id):
    try:
        engine.execute("DELETE FROM roster_user WHERE user_id ="+user_id+" AND team_id="+team_id)
    except SQLAlchemyError:
        stats['roster_user_failed_to_remove'] += 1
        stats['sql_errors'] += 1
        logger.exception('Failed to delete roster user %s from roster_user %s', user_id, team_id)
        raise


def get_schedule(engine, team_id, roster_id, role_id):
    try:
        schedule_id = engine.execute('SELECT * FROM schedule WHERE ' +
                       'team_id=' + str(team_id) + ',' +
                       'roster_id=' + str(roster_id) + ',' +
                       'role_id=' + str(role_id) + ',' +
                       ')').lastrowid
    except SQLAlchemyError as e:
        return False
    return schedule_id


def get_schedule_events(engine, schedule_id):
    events = []
    try:
        res = engine.execute('SELECT * FROM schedule_events WHERE ' +
                       'schedule_id=' + str(schedule_id) + ',' +
                       ')')
        for row in res:
            events.append({ 'start': row.start, 'duration': row.duration})
    except SQLAlchemyError as e:
        return False
    return events


def insert_schedule(engine, team_id, roster_id, role_id,
        auto_populate_threshold, advanced_mode, last_epoch_scheduled,
        last_scheduled_user_id, scheduler_id):
    try:
        schedule_id = engine.execute('INSERT INTO schedule VALUES(NULL, ' +
                       str(team_id) + ',' +
                       str(roster_id) + ',' +
                       str(role_id) + ',' +
                       str(auto_populate_threshold) + ',' +
                       str(advanced_mode) + ',' +
                       str(last_epoch_scheduled) + ',' +
                       str(last_scheduled_user_id) + ',' +
                       str(scheduler_id) +
                       ')').lastrowid
    except SQLAlchemyError as e:
        stats['schedule_failed_to_add'] += 1
        stats['sql_errors'] += 1
        logger.exception('Failed to add schedule for team_id %s', team_id)
        raise
    return schedule_id


# special. will remove all schedules and schedule events for team_id
def delete_team_schedules(engine, team_id):
    try:
        res = engine.execute('SELECT `id` FROM schedule WHERE team_id='+str(team_id)+')')
        for row in res:
            engine.execute('DELETE FROM schedule_event WHERE schedule_id='+str(row.id)+')')
        engine.execute('DELETE FROM schedule WHERE team_id='+str(team_id)+')')
    except SQLAlchemyError:
        stats['schedule_failed_to_remove'] += 1
        stats['sql_errors'] += 1
        logger.exception('Failed to remove schedules for team_id %s', team_id)
        raise


def insert_schedule_event(engine, schedule_id, start, duration):
    try:
        engine.execute('INSERT INTO schedule_event VALUES(NULL, ' +
                       str(schedule_id) + ',' +
                       str(start) + ',' +
                       str(duration) + ')')
    except SQLAlchemyError:
        stats['schedule_event_failed_to_add'] += 1
        stats['sql_errors'] += 1
        logger.exception('Failed to add schedule event to %s with start %s', schedule_id, start)
        raise


def add_teams(engine, teams, ldap_teams):
    # Use replace here, to overwrite existing, but deactivated teams
    team_add_sql = 'REPLACE INTO `team` (`name`, `slack_channel`, `email`, `scheduling_timezone`, `active`, `iris_plan`, `iris_enabled`) VALUES (%s, %s, %s, %s, 1, NULL, 0)'

    for team in teams:
        logger.info('Inserting team %s', team)
        teamname = team.replace('ad-', '')
        try:
            team_id = engine.execute(team_add_sql, (team, "#"+teamname, teamname+"@bol.com", "Europe/Amsterdam")).lastrowid
        except SQLAlchemyError:
            stats['teams_failed_to_add'] += 1
            stats['sql_errors'] += 1
            logger.exception('Failed to add team %s', team)
            continue
        stats['teams_added'] += 1

        set_team_admins(engine, team, ldap_teams[team]['members'])

        # add dummy user for team, to set up default roster and schedule
        modes = dict(list(engine.execute('SELECT `name`, `id` FROM `contact_mode`')))
        dummy_ldap_user = get_dummy_ldap_user(ldap_teams[team]['phonenumber'], team)
        dummy_user_id = insert_user(engine, team, dummy_ldap_user, modes)
        insert_team_user(engine, team_id, dummy_user_id)

        # add default roster and schedule
        roster_id = insert_roster(engine, team+"-default", team_id)
        insert_roster_user(engine, roster_id, dummy_user_id, 1, 0)

        # different default schedules for standby teams
        teamtype = 'officehours'
        if teamname in STANDBYTEAMS or teamname in STANDBYESCALATIONTEAMS:
            teamtype = 'standby'

        insert_team_schedule_defaults(engine, team_id, roster_id, teamtype)


def get_dummy_ldap_user(phonenumber, team):
    sane_team = team.replace("ad-", "")

    hipchat = "Team " + sane_team[4:] + " Alerts"
    email = sane_team + '@bol.com'
    if sane_team in SCRUMTEAMS:
        if 'hipchat_room' in SCRUMTEAMS[sane_team]:
            hipchat = SCRUMTEAMS[sane_team]['hipchat_room']
        if 'email_address' in SCRUMTEAMS[sane_team]:
            email = SCRUMTEAMS[sane_team]['email_address']
        if 'mobile_phone' in SCRUMTEAMS[sane_team]:
            phonenumber = SCRUMTEAMS[sane_team]['mobile_phone']

    ldap_user = {'sms': phonenumber,
                 'call': phonenumber,
                 'email': email,
                 'name': team,
                 'hipchat': hipchat,
                 'slack': team}
    return ldap_user


def remove_teams(engine, teams):
    for team in teams:
        logger.info('Deactivating team %s', team)
        try:
            engine.execute('UPDATE team SET active = FALSE WHERE name = %s', team)
        except SQLAlchemyError:
            stats['teams_failed_to_deactivate'] += 1
            stats['sql_errors'] += 1
            logger.exception('Failed to deactivate team %s' % team)
            continue

        # remove team dummy user and roster user
        team_id = get_team_id(engine, team)
        roster_user_id = get_user_id(engine, team)
        if roster_user_id:
            delete_roster_user(engine, team_id, roster_user_id)
        delete_team_schedules(engine, team_id)
        prune_user(engine, team)
        stats['teams_deactivated'] += 1


def insert_team_schedule_defaults(engine, team_id, roster_id, teamtype):
    auto_populate_threshold = 120
    advanced_mode = 1
    last_epoch_scheduled = "NULL"
    last_scheduled_user_id = "NULL"
    scheduler_id = 1  # default scheduler
    role_id = 1  # primary

    if teamtype == 'officehours':
        duration = "36000"  # 10 hours in seconds
        default_schedule_event_start_offsets = [
                "115200",
                "201600",
                "288000",
                "374400",
                "460800"
                ]

        schedule_id = insert_schedule(engine, team_id, roster_id, role_id,
                auto_populate_threshold, advanced_mode, last_epoch_scheduled,
                last_scheduled_user_id, scheduler_id)

        for start_offset in default_schedule_event_start_offsets:
            insert_schedule_event(engine, schedule_id, start_offset, duration)

    elif teamtype == 'standby':
        duration = "50400"  # 14 hours in seconds
        default_schedule_event_start_offsets = [
                "151200",
                "237600",
                "324000",
                "410400"
                ]

        schedule_id = insert_schedule(engine, team_id, roster_id, role_id,
                auto_populate_threshold, advanced_mode, last_epoch_scheduled,
                last_scheduled_user_id, scheduler_id)

        for start_offset in default_schedule_event_start_offsets:
            insert_schedule_event(engine, schedule_id, start_offset, duration)

        friday_till_monday_duration = "223200"  # friday 18:00 to monday 08:00
        weekend_schedule_event_start_offsets = [ '496800' ]

        for start_offset in weekend_schedule_event_start_offsets:
            insert_schedule_event(engine, schedule_id, start_offset, friday_till_monday_duration)



def set_team_roster(engine, team_id):
    team = get_team_name(engine, team_id)
    roster_id = get_roster(engine, team+"-default")
    if not roster_id:
        logger.info("Team %s missing default roster - inserting", get_team_name(engine, team_id))
        team = get_team_name(engine, team_id)
        dummy_user_id = get_user_id(engine, team)
        if dummy_user_id:
            roster_id = insert_roster(engine, team+"-default", team_id)
            insert_roster_user(engine, roster_id, dummy_user_id, 1, 0)
            insert_team_user(engine, team_id, dummy_user_id)
        else:
            logger.info("Failed to get dummy team user id. Cannot set team roster for %s", team)


# Immutable: team admins, dummy roster
def update_teams(engine, teams, ldap_teams):
    for team in teams:
        team_id = get_team_id(engine, team)
        set_team_admins(engine, team, ldap_teams[team]['members'])
        set_team_roster(engine, team_id)


def sync_teams(config, engine, ldap_users):
    teams_query = '''SELECT `team`.`name` as `name`,
                            `team`.`slack_channel` as `slack_channel`,
                            `team`.`email` as `email`,
                            `team`.`scheduling_timezone` as `scheduling_timezone`,
                            `team`.`iris_plan` as `iris_plan`,
                            `team`.`iris_enabled` as `iris_enabled`
                     FROM `team` WHERE `active`=1
                     ORDER BY `team`.`name`'''

    oncall_teams = {}
    for row in engine.execute(teams_query):
        oncall_teams.setdefault(row.name, {})

    # "ad-" is the magic prefix we use to determine we're
    # responsible for this team
    oncall_teamnames = [x for x in set(oncall_teams) if x.startswith('ad-')]
    oncall_teamnames = set(oncall_teamnames)

    # teams from ldap
    ldap_teams = get_ldap_teams(ldap_users)
    ldap_teamnames = set(ldap_teams)

    # set of ldap teams not in oncall
    teams_to_insert = ldap_teamnames - oncall_teamnames
    # set of existing oncall teams that are in ldap
    teams_to_update = oncall_teamnames & ldap_teamnames
    # set of teams in oncall but not ldap, assumed to be inactive
    inactive_teams = oncall_teamnames - ldap_teamnames

    add_teams(engine, teams_to_insert, ldap_teams)
    remove_teams(engine, inactive_teams)
    update_teams(engine, teams_to_update, ldap_teams)


def insert_user(engine, username, ldap_user, modes):
    logger.debug('Inserting user %s', username)

    user_add_sql = 'REPLACE INTO `user` (`name`, `full_name`, `photo_url`) VALUES (%s, %s, %s)'

    full_name = ldap_user.pop('name')
    try:
        photo_url_tpl = LDAP_SETTINGS.get('image_url')
        photo_url = photo_url_tpl % username if photo_url_tpl else None
        user_id = engine.execute(user_add_sql, (username, full_name, photo_url)).lastrowid
    except SQLAlchemyError:
        stats['users_failed_to_add'] += 1
        stats['sql_errors'] += 1
        logger.exception('Failed to add user %s' % username)
        return

    stats['users_added'] += 1

    for key, value in ldap_user.iteritems():
        if value and key in modes:
            logger.debug('\tmode: %s -> %s' % (key, value))
            user_contact_add_sql = 'INSERT INTO `user_contact` (`user_id`, `mode_id`, `destination`) VALUES (%s, %s, %s)'
            engine.execute(user_contact_add_sql, (user_id, modes[key], value))

    return user_id


def sync(config, engine):
    Session = sessionmaker(bind=engine)
    session = Session()
    oncall_users = {}
    users_query = '''SELECT `user`.`name` as `name`, `contact_mode`.`name` as `mode`, `user_contact`.`destination`,
                            `user`.`full_name`, `user`.`photo_url`
                     FROM `user`
                     LEFT OUTER JOIN `user_contact` ON `user`.`id` = `user_contact`.`user_id`
                     LEFT OUTER JOIN `contact_mode` ON `user_contact`.`mode_id` = `contact_mode`.`id`
                     ORDER BY `user`.`name`'''
    for row in engine.execute(users_query):
        contacts = oncall_users.setdefault(row.name, {})
        contacts['full_name'] = row.full_name
        contacts['photo_url'] = row.photo_url
        if row.mode is None or row.destination is None:
            logger.info("No user_contact info for %s currently in oncall", row.name)
            continue
        contacts[row.mode] = row.destination

    oncall_usernames = set(oncall_users)

    # users from ldap and config file
    ldap_users, ldap_user_dns = fetch_ldap()
    stats['ldap_found'] += len(ldap_users)
    ldap_users.update(get_predefined_users(config))
    ldap_usernames = set(ldap_users)

    # set of ldap users not in oncall
    users_to_insert = ldap_usernames - oncall_usernames
    # set of existing oncall users that are in ldap
    users_to_update = oncall_usernames & ldap_usernames
    # set of users in oncall but not ldap, assumed to be inactive
    # Filter our "^ad-.*" users, which are dummy users associated with team accounts.
    oncall_usernames_filtered = set([x for x in oncall_usernames if not x.startswith('ad-')])
    inactive_users = oncall_usernames_filtered - ldap_usernames
    # users who need to be deactivated
    if inactive_users:
        rows = engine.execute('SELECT name FROM user WHERE active = TRUE AND name IN %s', inactive_users)
        users_to_purge = (user.name for user in rows)
    else:
        users_to_purge = []

    # set of inactive oncall users who appear in ldap
    rows = engine.execute('SELECT name FROM user WHERE active = FALSE AND name IN %s', ldap_usernames)
    users_to_reactivate = (user.name for user in rows)

    # get objects needed for insertion
    modes = dict(list(session.execute('SELECT `name`, `id` FROM `contact_mode`')))

    # insert users that need to be
    for username in users_to_insert:
        insert_user(engine, username, ldap_users[username], modes)

    # update users that need to be
    contact_update_sql = 'UPDATE user_contact SET destination = %s WHERE user_id = (SELECT id FROM user WHERE name = %s) AND mode_id = %s'
    contact_insert_sql = 'INSERT INTO user_contact (user_id, mode_id, destination) VALUES ((SELECT id FROM user WHERE name = %s), %s, %s)'
    contact_delete_sql = 'DELETE FROM user_contact WHERE user_id = (SELECT id FROM user WHERE name = %s) AND mode_id = %s'
    name_update_sql = 'UPDATE user SET full_name = %s WHERE name = %s'
    photo_update_sql = 'UPDATE user SET photo_url = %s WHERE name = %s'
    for username in users_to_update:
        try:
            db_contacts = oncall_users[username]
            ldap_contacts = ldap_users[username]
            full_name = ldap_contacts.pop('name')
            if full_name != db_contacts.get('full_name'):
                logger.info("%s: full_name -> %s", username, full_name)
                engine.execute(name_update_sql, (full_name, username))
                stats['user_names_updated'] += 1
            if not db_contacts.get('photo_url'):
                photo_url_tpl = LDAP_SETTINGS.get('image_url')
                photo_url = photo_url_tpl % username if photo_url_tpl else None
                engine.execute(photo_update_sql, (photo_url, username))
                stats['user_photos_updated'] += 1
            # we only sync contact modes during the initial import
            # for mode in modes:
            #     if mode in ldap_contacts and ldap_contacts[mode]:
            #         if mode in db_contacts:
            #             if ldap_contacts[mode] != db_contacts[mode]:
            #                 logger.info("%s: mode -> %s", username, mode)
            #                 engine.execute(contact_update_sql, (ldap_contacts[mode], username, modes[mode]))
            #                 stats['user_contacts_updated'] += 1
            #         else:
            #             logger.info("%s: adding mode %s", username, mode)
            #             engine.execute(contact_insert_sql, (username, modes[mode], ldap_contacts[mode]))
            #             stats['user_contacts_updated'] += 1
            #     elif mode in db_contacts:
            #         logger.info("%s: deleting mode %s", username, mode)
            #         engine.execute(contact_delete_sql, (username, modes[mode]))
            #         stats['user_contacts_updated'] += 1
            #     else:
            #         # allow missing call and sms modes, as not everyone has a phone
            #         if not mode in ['call', 'sms']:
            #             logger.info("%s: missing mode %s", username, mode)
        except SQLAlchemyError:
            stats['users_failed_to_update'] += 1
            stats['sql_errors'] += 1
            logger.exception('Failed to update user %s' % username)
            continue

    for username in users_to_purge:
        prune_user(engine, username)

    for username in users_to_reactivate:
        try:
            logger.info('Reactivating: %s', username)
            engine.execute('UPDATE user SET active = TRUE WHERE name = %s', username)
            stats['users_reactivated'] += 1
        except SQLAlchemyError:
            stats['users_failed_to_reactivate'] += 1
            stats['sql_errors'] += 1
            logger.exception('Failed to reactivate user %s', username)

    session.commit()
    session.close()

    # make teams
    sync_teams(config, engine, ldap_user_dns)


def metrics_sender():
    while True:
        metrics.emit_metrics()
        sleep(60)


def main(config):
    global LDAP_SETTINGS
    global SCRUMTEAMS
    global STANDBYTEAMS
    global STANDBYESCALATIONTEAMS

    LDAP_SETTINGS = config['ldap_sync']
    STANDBYTEAMS = config['ldap_sync']['standby_teams']
    STANDBYESCALATIONTEAMS = config['ldap_sync']['standby_escalation_teams']
    teamsfile = config['ldap_sync']['scrumteams_file']

    with open(teamsfile, 'r') as stream:
        try:
            SCRUMTEAMS = yaml.load(stream)
        except yaml.YAMLError as err:
            logger.info(err)

    metrics.init(config, 'oncall-ldap-user-sync', stats)
    spawn(metrics_sender)
    # Default sleep one hour
    sleep_time = config.get('user_sync_sleep_time', 3600)
    engine = create_engine(config['db']['conn']['str'] % config['db']['conn']['kwargs'],
                           **config['db']['kwargs'])
    while 1:
        logger.info('Starting user sync loop at %s' % time.time())
        sync(config, engine)
        logger.info('Sleeping for %s seconds' % sleep_time)
        sleep(sleep_time)


if __name__ == '__main__':
    config_path = sys.argv[1]
    with open(config_path, 'r') as config_file:
        config = yaml.load(config_file)
    main(config)
