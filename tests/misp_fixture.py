"""Ordinary stateful flat-event fixture; never connects to MISP."""
from copy import deepcopy


def event(attrs=(), published=True):
    a = [dict({'id':str(i),'event_id':'1932'}, **row) for i,row in enumerate(attrs,1)]
    return {'Event':{'id':'1932','Attribute':a,'attribute_count':str(len(a)), 'published':published}}


def wire(client, attrs):
    ev = event(attrs)['Event']
    def add(**kw):
        a = {'id':str(len(ev['Attribute'])+1),'event_id':'1932','type':kw['type_'],'value':kw['value'],
             'to_ids':kw['to_ids'],'comment':kw['comment']}
        ev['Attribute'].append(a); ev['attribute_count']=str(len(ev['Attribute'])); ev['published']=False
        return {'Attribute':deepcopy(a)}
    def publish(_):
        ev['published']=True; ev['publish_timestamp']='updated'
        return {'message':'Published'}
    client.get_event.side_effect=lambda _: {'Event':deepcopy(ev)}
    client.add_attribute.side_effect=add; client.publish_event.side_effect=publish
    return ev
