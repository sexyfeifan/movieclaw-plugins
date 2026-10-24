import asyncio
import copy
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
from fastapi import FastAPI
from pt_pack.maintenance import Maintenance, inspect_html, signed_page, rule, same_url, identity, maintenance_router
from .test_assistant import FakeContext

UTC=timezone.utc
LOGIN='<a href="userdetails.php?id=12">fixture</a><a href="attendance.php">签到</a>'
SIGNED='<h2>签到成功</h2><p>连续签到 5 天</p>'
FORM='<form method="post" action="attendance.php"><input type="hidden" name="csrf" value="fixture-only-token"><button type="submit">签到</button></form>'
class NexusPHPSite: pass
class FakeSite(NexusPHPSite):
    base_url='https://fixture.example'
    def __init__(self,responses):
        self.responses=iter(responses);self.calls=[]
        self.client=SimpleNamespace(raw_get=self.get,raw_post=self.post)
    async def get(self,url,**kw):return self.response('GET',url,kw)
    async def post(self,url,**kw):return self.response('POST',url,kw)
    def response(self,method,url,kw):
        self.calls.append((method,url,kw));value=next(self.responses)
        if isinstance(value,Exception):raise value
        status,html,headers=value if len(value)==3 else (*value,{})
        return httpx.Response(status,text=html,headers=headers,request=httpx.Request(method,url))

class Parsing(unittest.TestCase):
    def test_no_http_success_or_old_history_as_signed_evidence(self):
        def r(s):return httpx.Response(200,text=s)
        self.assertFalse(signed_page(r('<p>欢迎签到</p>'),attendance=True))
        self.assertFalse(signed_page(r('<table><tr><td>去年签到成功</td></tr></table>'),attendance=True))
        self.assertTrue(signed_page(r(SIGNED),attendance=True))
        self.assertTrue(signed_page(r('<a href="attendance.php">已签到</a>')))
        self.assertFalse(signed_page(r('<script>签到成功</script>'),attendance=True))
    def test_wall_login_and_rate_limit_are_not_success(self):
        for status,html,state in [(403,'','blocked'),(429,'','rate_limited'),(200,'<input name="imagehash">','challenge'),(200,'<div class="cf-turnstile"></div>','challenge'),(200,'<input type="password">','login_required')]:
            self.assertEqual(inspect_html(httpx.Response(status,text=html)),state)
    def test_paths_cannot_escape_to_credentials_or_other_origins(self):
        for path in ['https://evil.example/attendance.php','../attendance.php','attendance.php?token=x','delete.php','attendance.php#x','%2e%2e/attendance.php']:
            with self.assertRaises(ValueError):rule({'path':path})
        self.assertEqual(same_url('https://fixture.example/attendance.php','attendance.php'),'https://fixture.example/attendance.php')
        with self.assertRaises(ValueError):same_url('https://fixture.example','https://evil.example/signin')

class Execution(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder=tempfile.TemporaryDirectory();self.ctx=FakeContext(self.folder.name)
        workspace=SimpleNamespace(data=self.ctx.data,files=self.ctx.files)
        self.now=datetime(2026,10,24,12,0,tzinfo=UTC)
        self.account={'site_id':'fixture','auth_type':'cookie','profile':{'username':'fixture-account'}}
        self.rows=[{'site_id':'fixture','name':'测试岛','usable':True,'_account':self.account}]
        self.snapshot=AsyncMock(side_effect=lambda:{'sites':self.rows})
        self.site=FakeSite([])
        self.service=Maintenance(self.ctx,workspace,self.snapshot,get_site=AsyncMock(side_effect=lambda sid:self.site),clock=lambda:self.now)
        self.service.ensure_worker=Mock()
        await self.service.start()
    async def asyncTearDown(self):self.folder.cleanup()
    def config(self):return {'revision':self.service.state['revision'],'timezone':'Asia/Shanghai','start':'08:00','end':'22:00','randomize':True,'sites':{'fixture':{'enabled':True,'action':'sign','rule':None}}}
    async def test_status_read_never_visits_site_and_does_not_expose_account(self):
        result=await self.service.view();self.service.get_site.assert_not_awaited()
        self.assertNotIn('fixture-account',str(result));self.assertEqual(result['sites'][0]['status'],'unknown')
    async def test_simple_get_and_post_attendance_and_daily_dedupe(self):
        self.site=FakeSite([(200,LOGIN),(200,FORM),(200,SIGNED)])
        await self.service.run('fixture');await self.service.run('fixture')
        self.assertEqual([c[0] for c in self.site.calls],['GET','GET','POST'])
        self.assertEqual(self.site.calls[-1][2]['data'],{'csrf':'fixture-only-token'})
        self.assertEqual((await self.service.view())['sites'][0]['status'],'signed')
        self.assertNotIn('fixture-only-token',str(self.ctx.values))
    async def test_get_attendance_already_success_does_not_post(self):
        self.site=FakeSite([(200,LOGIN),(200,SIGNED)])
        await self.service.run('fixture');self.assertEqual(len(self.site.calls),2)
    async def test_captcha_does_not_submit_or_retry_automatically(self):
        await self.service.configure(self.config());self.site=FakeSite([(200,LOGIN),(200,'<input name="imagestring">')])
        await self.service.run('fixture',automatic=True);await self.service.tick()
        self.assertEqual(len(self.site.calls),2);self.assertEqual((await self.service.view())['sites'][0]['status'],'challenge')
    async def test_manual_check_is_read_only_even_if_attendance_get_is_mutating(self):
        self.site=FakeSite([(200,LOGIN)])
        await self.service.run('fixture','check');self.assertEqual(len(self.site.calls),1)
        self.assertEqual((await self.service.view())['sites'][0]['status'],'pending')
    async def test_post_redirect_confirmed_without_reposting(self):
        self.site=FakeSite([(200,LOGIN),(200,FORM),(303,'',{'location':'attendance.php'}),(200,SIGNED)])
        await self.service.run('fixture');self.assertEqual([c[0] for c in self.site.calls],['GET','GET','POST','GET'])
        self.assertEqual((await self.service.view())['sites'][0]['status'],'signed')
    async def test_ambiguous_response_never_claims_success(self):
        self.site=FakeSite([(200,LOGIN),(200,'<p>签到中心</p>')])
        await self.service.run('fixture');self.assertEqual((await self.service.view())['sites'][0]['status'],'uncertain')
    async def test_historical_or_paid_forms_are_never_submitted(self):
        for field in ['<input type="hidden" name="date" value="2026-10-22">','<input type="hidden" name="action" value="retroactive">','<input type="hidden" name="card" value="1">']:
            self.service.state['records'].clear()
            self.site=FakeSite([(200,LOGIN),(200,FORM.replace('<button',field+'<button'))])
            await self.service.run('fixture')
            self.assertEqual(len(self.site.calls),2)
            self.assertEqual((await self.service.view())['sites'][0]['status'],'uncertain')
    async def test_random_daily_slots_restart_unique_and_revision(self):
        self.rows.extend({**self.rows[0],'site_id':f's{i}'} for i in range(25))
        cfg=self.config();cfg['sites']={r['site_id']:{'enabled':True,'action':'sign','rule':None} for r in self.rows}
        await self.service.configure(cfg)
        slots=self.service.slots(self.service.local().date());self.assertEqual(len(slots),26);self.assertEqual(len(set(slots.values())),26)
        self.assertTrue(all(480<=v<=1320 for v in slots.values()))
        same=Maintenance(self.ctx,SimpleNamespace(data=self.ctx.data,files=self.ctx.files),self.snapshot)
        same.ensure_worker=Mock();await same.start()
        self.assertEqual(slots,same.slots(self.service.local().date()))
        self.assertNotEqual(slots,same.slots(self.service.local().date()+timedelta(days=1)))
        with self.assertRaises(Exception):await self.service.configure(cfg)
    async def test_restart_interruption_is_not_replayed(self):
        await self.service.configure(self.config())
        await self.service.update('fixture',status='running',day=self.service.local().date().isoformat(),attempt_day=self.service.local().date().isoformat(),account=identity(self.account))
        same=Maintenance(self.ctx,SimpleNamespace(data=self.ctx.data,files=self.ctx.files),self.snapshot,get_site=self.service.get_site,clock=lambda:self.now)
        same.ensure_worker=Mock();await same.start();await same.tick()
        self.service.get_site.assert_not_awaited();self.assertEqual((await same.view())['sites'][0]['status'],'interrupted')
    async def test_unconfigured_paused_and_removed_sites_never_run(self):
        await self.service.configure(self.config());self.rows[0]['usable']=False
        await self.service.run('fixture');await self.service.tick();self.service.get_site.assert_not_awaited()
    async def test_account_change_does_not_inherit_signed(self):
        self.site=FakeSite([(200,LOGIN),(200,SIGNED)]);await self.service.run('fixture')
        self.account['profile']['username']='different-account'
        self.assertEqual((await self.service.view())['sites'][0]['status'],'unknown')
    async def test_manual_visit_does_not_cancel_later_auto_sign(self):
        self.site=FakeSite([(200,LOGIN)])
        await self.service.run('fixture','visit')
        self.assertNotIn('attempt_day',self.service.state['records']['fixture'])
    async def test_daily_tick_executes_once_and_next_day_resets(self):
        await self.service.configure(self.config());self.now=self.now.replace(hour=15)
        self.site=FakeSite([(200,LOGIN),(200,SIGNED)])
        await self.service.tick();await self.service.tick();self.assertEqual(len(self.site.calls),2)
        self.now+=timedelta(days=1);self.site=FakeSite([(200,LOGIN),(200,SIGNED)])
        await self.service.tick();self.assertEqual(len(self.site.calls),2)
        self.assertEqual((await self.service.view())['sites'][0]['status'],'signed')
    async def test_stop_plan_prevents_queued_automatic_execution(self):
        cfg=self.config();cfg['sites']['fixture']['enabled']=False
        await self.service.configure(cfg);await self.service.run('fixture',automatic=True)
        self.service.get_site.assert_not_awaited()
    async def test_cross_origin_posts_rejected(self):
        app=FastAPI();app.include_router(maintenance_router(self.service))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url='http://testserver') as c:
            for path in ['/maintenance/plan','/maintenance/fixture/sign']:
                self.assertEqual((await c.post(path,json={},headers={'Origin':'https://evil.example'})).status_code,403)
                self.assertEqual((await c.post(path,json={})).status_code,403)
    async def test_concurrent_click_only_one_execution(self):
        gate=asyncio.Event();original=self.service.get_site
        async def get(sid):await gate.wait();return self.site
        self.service.get_site=get;self.site=FakeSite([(200,LOGIN),(200,SIGNED)])
        one=asyncio.create_task(self.service.run('fixture'));await asyncio.sleep(0)
        two=asyncio.create_task(self.service.run('fixture'));gate.set();await asyncio.gather(one,two)
        self.assertEqual(len(self.site.calls),2)
