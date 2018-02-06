#!/usr/bin/env python

### TODO:
### - test dummy user creation
### - test default roster
### - test default schedule

import requests
import time
from testutils import prefix, api_v0

import yaml, os, pytest
from sqlalchemy import create_engine
from oncall import db
from oncall.user_sync.ldap_sync_bol import add_teams, generate_oncall_teams

# required by conftest
test_user = 'test_user'


# Read config based on pytest root directory. Assumes config lives at oncall/configs/config.yaml
cfg_path = os.path.join(str(pytest.config.rootdir), 'configs/config.yaml')
with open(cfg_path) as f:
    config = yaml.load(f)

engine = create_engine(config['db']['conn']['str'] % config['db']['conn']['kwargs'], **config['db']['kwargs'])


@prefix('test_ldap_sync_bol_create_team')
def test_ldap_sync_bol_create_team(team):
    ldap_teams = {
                   'team1x-24x7-builtin':
                   {
                      'phonenumber': ['+3112341234'],
                      'members': ['wleese', 'tvlieg']
                   },
                   'team2b-workhours-builtin':
                   {
                      'phonenumber': ['+3112341234'],
                      'members': ['roverdijk', 'lvanroon']
                   }
                 }
    teams_to_insert = set(['team1x-24x7-builtin', 'team2b-workhours-builtin'])

    add_teams(engine, teams_to_insert, ldap_teams)

    re = requests.get(api_v0('teams'))
    assert re.status_code == 200
    teams = re.json()
    assert isinstance(teams, list)
    assert len(teams) >= 1

    # Add to team fixture to ensure cleanup
    for teamname in teams_to_insert:
        assert teamname in teams
        team.mark_for_cleaning(teamname)


@prefix('test_ldap_sync_bol_generate_oncall_teams_scrum_teams')
def test_ldap_sync_bol_generate_oncall_teams_scrum_teams(team):
    ldap_teams = {
                   'team1x':
                   {
                      'phonenumber': ['+3112341234'],
                      'members': ['wleese', 'tvlieg']
                   }
                 }

    team_type = 'scrumteam'
    oncall_teams = generate_oncall_teams(ldap_teams, team_type)

    assert isinstance(oncall_teams, dict)
    assert 'team1x-24x7-builtin' in oncall_teams
    assert 'team1x-workhours-builtin' in oncall_teams
    assert 'team1x-standby-builtin' not in oncall_teams

    for team in oncall_teams:
        assert 'members' in oncall_teams[team]
        assert 'phonenumber' in oncall_teams[team]

        if team == 'team1x-24x7-builtin':
            assert oncall_teams[team]['members'] == ['wleese', 'tvlieg']
        elif team == 'team1x-workhours-builtin':
            assert oncall_teams[team]['members'] == ['wleese', 'tvlieg']


@prefix('test_ldap_sync_bol_generate_oncall_teams_itops_teams')
def test_ldap_sync_bol_generate_oncall_teams_itops_teams(team):
    ldap_teams = { 'srt-shopping':
                   {
                      'phonenumber': ['+3112341234'],
                      'members': ['wleese', 'tvlieg']
                   }
                 }

    team_type = 'itops'
    oncall_teams = generate_oncall_teams(ldap_teams, team_type)

    assert isinstance(oncall_teams, dict)
    assert 'srt-shopping-24x7-builtin' in oncall_teams
    assert 'srt-shopping-workhours-builtin' in oncall_teams
    assert 'srt-shopping-standby-builtin' not in oncall_teams

    for team in oncall_teams:
        assert 'members' in oncall_teams[team]
        assert 'phonenumber' in oncall_teams[team]

        if team == 'srt-shopping-24x7-builtin':
            assert oncall_teams[team]['members'] == ['wleese', 'tvlieg']
        elif team == 'srt-shopping-workhours-builtin':
            assert oncall_teams[team]['members'] == ['wleese', 'tvlieg']


@prefix('test_ldap_sync_bol_generate_oncall_teams_standby_teams')
def test_ldap_sync_bol_generate_oncall_teams_standby_teams(team):
    ldap_teams = { 'middleware':
                   {
                      'phonenumber': ['+3112341234'],
                      'members': ['wleese', 'tvlieg']
                   }
                 }

    team_type = 'standby'
    oncall_teams = generate_oncall_teams(ldap_teams, team_type)

    assert isinstance(oncall_teams, dict)
    assert 'middleware-24x7-builtin' in oncall_teams
    assert 'middleware-standby-builtin' in oncall_teams
    assert 'middleware-workhours-builtin' not in oncall_teams

    for team in oncall_teams:
        assert 'members' in oncall_teams[team]
        assert 'phonenumber' in oncall_teams[team]

        if team == 'middleware-24x7-builtin':
            assert oncall_teams[team]['members'] == ['wleese', 'tvlieg']
        elif team == 'middleware-workhours-builtin':
            assert oncall_teams[team]['members'] == ['wleese', 'tvlieg']
