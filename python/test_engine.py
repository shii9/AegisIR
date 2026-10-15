import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import engine

class EngineTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.env=patch.dict(os.environ, {'AEGISIR_HOME': self.temp.name}, clear=False)
        self.env.start()
        self.conn=engine.db()
        self.case=engine.create(self.conn,{'title':'Unit Test','asset':'lab','analyst':'analyst','severity':'high'})['case_id']
    def tearDown(self):
        self.conn.close()
        self.env.stop()
        self.temp.cleanup()
    def test_demo_findings_and_approval(self):
        result=engine.ingest(self.conn,self.case,{'modules':engine.demo_modules()})
        self.assertGreaterEqual(result['total_findings'],4)
        f=self.conn.execute("SELECT * FROM findings WHERE case_id=? AND action_type='terminate_process'",(self.case,)).fetchone()
        self.assertIsNotNone(f)
        self.assertEqual(engine.action_plan(self.conn,self.case,f['id'])['decision'],'pending')
        with self.assertRaises(ValueError):engine.prepare_action(self.conn,self.case,f['id'])
        engine.decisions(self.conn,self.case,f['id'],'approve','Reviewed sample against lab evidence')
        self.assertEqual(engine.prepare_action(self.conn,self.case,f['id'])['action_type'],'terminate_process')
        engine.decisions(self.conn,self.case,f['id'],'skip','No live action on this endpoint')
        self.assertEqual(engine.check_finding(self.conn,self.case,f['id'])['decision'],'skip')
    def test_synthetic_actions_rejected(self):
        cid=engine.create(self.conn,{'title':'demo','asset':'x','analyst':'me'},True)['case_id']
        engine.ingest(self.conn,cid,{'modules':engine.demo_modules()})
        f=self.conn.execute("SELECT id FROM findings WHERE case_id=? AND action_type!='' LIMIT 1",(cid,)).fetchone()[0]
        engine.decisions(self.conn,cid,f,'approve','Approved only for synthetic unit test')
        with self.assertRaisesRegex(ValueError,'synthetic'):engine.prepare_action(self.conn,cid,f)
    def test_tamper_detection(self):
        engine.ingest(self.conn,self.case,{'modules':engine.demo_modules()})
        self.assertTrue(engine.verify(self.conn,self.case)['integrity_ok'])
        r=self.conn.execute('SELECT evidence_path FROM scans WHERE case_id=? LIMIT 1',(self.case,)).fetchone()
        Path(r[0]).write_text('tampered')
        self.assertFalse(engine.verify(self.conn,self.case)['integrity_ok'])
    def test_audit_tamper_detected(self):
        self.conn.execute("UPDATE audits SET detail='changed' WHERE case_id=?",(self.case,));self.conn.commit()
        self.assertFalse(engine.verify(self.conn,self.case)['audit_chain_valid'])
    def test_close_enforces_workflow(self):
        engine.ingest(self.conn,self.case,{'modules':[{'module':'users','items':[{'username':'root','uid':0,'supplementary_groups':[]}],'warnings':[],'status':'ok'}]})
        with self.assertRaisesRegex(ValueError,'checklist'):engine.close(self.conn,self.case,'Incident is fully resolved and approved')
        for phase,items in engine.CHECKLIST.items():
            for item in items:engine.checklist_set(self.conn,self.case,phase,item,'Verified evidence in local test')
        self.assertEqual(engine.close(self.conn,self.case,'Incident is fully resolved and approved')['status'],'closed')
    def test_reject_empty_reason(self):
        engine.ingest(self.conn,self.case,{'modules':engine.demo_modules()})
        f=self.conn.execute('SELECT id FROM findings LIMIT 1').fetchone()[0]
        with self.assertRaises(ValueError):engine.decisions(self.conn,self.case,f,'skip','no')
    def test_detection_rules(self):
        f=engine.detect({'module':'users','items':[{'username':'helpdesk','uid':0,'supplementary_groups':[]}]})
        self.assertEqual(f[0]['rule'],'SECONDARY-UID0')
        self.assertFalse(engine.detect({'module':'users','items':[{'username':'root','uid':0,'supplementary_groups':[]}]}))
    def test_report_refuses_overwrite(self):
        engine.ingest(self.conn,self.case,{'modules':engine.demo_modules()})
        path=str(Path(self.temp.name)/'incident.md')
        result=engine.report(self.conn,self.case,path)
        self.assertTrue(Path(result['path']).is_file())
        with self.assertRaisesRegex(ValueError,'exists'):engine.report(self.conn,self.case,path)
    def test_path_validation(self):
        with self.assertRaises(ValueError):engine.check_case(self.conn,'../../etc/passwd')
        with self.assertRaises(ValueError):engine.check_finding(self.conn,self.case,'oops')

if __name__=='__main__': unittest.main()
