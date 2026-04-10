
import logging
logger = logging.getLogger(__name__)

from bottle import route, get, post, delete
from bottle import request, response


def error(code, message):
    response.status = code
    message['status'] = code
    return message


get_user_table = lambda db: db.get_table('users', primary_id='userid', primary_type='String(100)')

@get('/users/<userid>')
def get_user(db, userid):
    user_table = get_user_table(db)
    user = user_table.find_one(userid=userid)
    if not user: 
        return error(404, {'error': 'Not a valid user'})
    else: 
        group_table = db.get_table('groups')
        groups = group_table.distinct('name', userid=userid)
        user['groups'] =sorted( [x['name'] for x in groups] )
        return user

@delete('/users/<userid>')
def delete_user(db, userid):
    user_table = get_user_table(db)
    user = user_table.find_one(userid=userid)
    if not user:
        return error(404, {'error': 'userid not found'})
    else:
        user_table.delete(userid=userid)
        return {'status': 200}


@route('/users/<userid>', method=['POST', 'PUT'])
def create__update_user(db, userid):
    data = request.json
    data_keys = data.keys()
    required_fields = ['first_name', 'last_name', 'userid', 'groups']
    missing_fields = [x for x in required_fields if x not in data_keys]
    extra_fields = [x for x in data_keys if x not in required_fields]
    if missing_fields:
        return error(400, {'error': 'Missing fields (%s)' % (','.join(missing_fields)) })
    if extra_fields:
        return error(400, {'error': 'Extra fields (%s)' % (','.join(extra_fields)) })

    user_table = get_user_table(db)
    existing_user = user_table.find_one(userid=data['userid'])
    if request.method == 'POST' and existing_user:
        return error(409, {'error': 'User already exists'})
    if request.method == 'PUT' and not existing_user:
        return error(404, {'error': 'User does not exist'})

    #update this user's group membership
    userid = data.get('userid')
    groups = data.pop('groups')
    groups_table = db.get_table('groups')

    if request.method == 'POST':
        user_insert = user_table.insert(data)
    elif request.method == 'PUT':
        user_update = user_table.update(data, ['userid'])

    for name in groups:
        groups_table.upsert(dict(name=name, userid=userid), ['name','userid'])

    if request.method == 'PUT':
        #get rid of any old groups for this user
        q = '''DELETE FROM groups 
                WHERE userid='{userid}'
                            AND name not in ({group_names})
              '''.format(userid=userid, group_names=','.join(["'%s'" % x for x in groups]))
        db.query(q)

    return {'status': 200, 'user': get_user(db, userid)}
