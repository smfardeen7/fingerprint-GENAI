import copy, json, shutil, struct, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import numpy as np
import pandas as pd
from genai_fingerprint.packets import import_capture,validate_packets,capture_records,ip_metadata
from genai_fingerprint.features import extract_features,feature_names
from genai_fingerprint.synthetic import write_pcap,generate
from genai_fingerprint.dataset import load_manifest
from genai_fingerprint.acquire import network_plan,network_change
from genai_fingerprint.models import paired_group_intervals

class PacketTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.p=pd.DataFrame({'timestamp':[100.,100.2,101.,105.], 'length':[40,100,1000,80], 'direction':[1,-1,1,-1]})
    def tearDown(self):self.temp.cleanup()
    def test_pcap_roundtrip_metadata(self):
        write_pcap(self.p,self.root/'x.pcap')
        stats=import_capture(self.root/'x.pcap',self.root/'x.csv',['192.0.2.10'])
        self.assertEqual(stats['imported'],4)
        pd.testing.assert_frame_equal(pd.read_csv(self.root/'x.csv'),self.p,check_dtype=False)
    def test_big_endian_pcap(self):
        write_pcap(self.p,self.root/'le.pcap');data=(self.root/'le.pcap').read_bytes()
        converted=struct.pack('>IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1);pos=24
        while pos<len(data):
            vals=struct.unpack_from('<IIII',data,pos);pos+=16
            converted+=struct.pack('>IIII',*vals)+data[pos:pos+vals[2]];pos+=vals[2]
        (self.root/'be.pcap').write_bytes(converted)
        self.assertEqual(len(list(capture_records(self.root/'be.pcap'))),4)
    def test_pcapng_enhanced_packets(self):
        write_pcap(self.p,self.root/'x.pcap');records=list(capture_records(self.root/'x.pcap'))
        def block(kind,body):
            body+=bytes((-len(body))%4);n=12+len(body)
            return struct.pack('<II',kind,n)+body+struct.pack('<I',n)
        data=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack('<HHI',1,0,65535))
        for ts,link,raw in records:
            tick=round(ts*1e6);data+=block(6,struct.pack('<IIIII',0,tick>>32,tick&0xffffffff,len(raw),len(raw))+raw)
        (self.root/'x.pcapng').write_bytes(data)
        import_capture(self.root/'x.pcapng',self.root/'ng.csv',['192.0.2.10'])
        pd.testing.assert_frame_equal(pd.read_csv(self.root/'ng.csv'),self.p,check_dtype=False)
    def test_ipv6_metadata(self):
        import ipaddress
        raw=struct.pack('!IHBB',6<<28,16,17,64)+ipaddress.ip_address('2001:db8::1').packed+ipaddress.ip_address('2001:db8::2').packed
        src,dst,size=ip_metadata(101,raw)
        self.assertEqual((src,dst,size),('2001:db8::1','2001:db8::2',56))
    def test_vlan_and_sll(self):
        write_pcap(self.p,self.root/'x.pcap');_,_,raw=next(capture_records(self.root/'x.pcap'))
        vlan=raw[:12]+b'\x81\x00\x00\x01'+raw[12:]
        self.assertEqual(ip_metadata(1,raw),ip_metadata(1,vlan))
        sll=bytes(14)+b'\x08\x00'+raw[14:]
        self.assertEqual(ip_metadata(1,raw),ip_metadata(113,sll))
    def test_truncation_rejected(self):
        (self.root/'bad').write_bytes(b'\xd4\xc3\xb2\xa1'+bytes(8))
        with self.assertRaises(ValueError):list(capture_records(self.root/'bad'))
    def test_unknown_device_rejected(self):
        write_pcap(self.p,self.root/'x.pcap')
        with self.assertRaises(ValueError):import_capture(self.root/'x.pcap',self.root/'x.csv',['192.0.2.99'])
    def test_payload_identifier_columns_rejected(self):
        with self.assertRaises(ValueError):validate_packets(self.p.assign(ip='192.0.2.10'))
    def test_nonfinite_and_bad_direction(self):
        with self.assertRaises(ValueError):validate_packets(self.p.assign(length=np.inf))
        with self.assertRaises(ValueError):validate_packets(self.p.assign(direction=0))
    def test_prefix_causality_and_boundary(self):
        a=extract_features(self.p,100,5)
        changed=self.p.copy();changed.loc[3,'length']=1480
        self.assertEqual(a,extract_features(changed,100,5))
        self.assertAlmostEqual(a['volume_packets_per_s'],3/5)
        self.assertAlmostEqual(a['volume_bytes_per_s'],1140/5)
    def test_single_direction_finite(self):
        vals=extract_features(self.p.assign(direction=1),100,5)
        self.assertTrue(all(np.isfinite(v) for v in vals.values()))
        self.assertEqual(vals['direction_up_byte_fraction'],1)
    def test_feature_allowlist(self):
        cols=list(extract_features(self.p,100,5))+['service','is_genai','ready_time','label','profile']
        for subset in ['full','volume','size','timing']:
            self.assertFalse(set(feature_names(cols,subset))&{'service','is_genai','ready_time','label','profile'})
    def test_absolute_clock_invariance(self):
        a=extract_features(self.p,100,5)
        b=extract_features(self.p.assign(timestamp=self.p.timestamp+10000),10100,5)
        for k in a:self.assertAlmostEqual(a[k],b[k],places=8)

class DatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name)
        cls.manifest=generate(cls.root/'synthetic',seed=8,groups=10)
        cls.df=pd.read_csv(cls.manifest)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def check_changed(self,df,message):
        file=self.manifest.parent/'altered.csv';df.to_csv(file,index=False)
        with self.assertRaisesRegex(ValueError,message):load_manifest(file,check_files=False)
    def test_valid_grouped_manifest(self):
        _,audit=load_manifest(self.manifest)
        self.assertEqual(audit['sessions'],180);self.assertEqual(audit['provenance'],'synthetic')
    def test_scenario_leakage_rejected(self):
        d=self.df.copy();d.loc[0,'scenario_group']=d.loc[d.split=='test','scenario_group'].iloc[0]
        self.check_changed(d,'Scenario leakage')
    def test_day_leakage_rejected(self):
        d=self.df.copy();d.loc[d.split=='test','date']='2026-09-01';self.check_changed(d,'day leakage')
    def test_mixed_provenance_rejected(self):
        d=self.df.copy();d.loc[0,'provenance']='real';self.check_changed(d,'never mix')
    def test_missing_class_rejected(self):
        d=self.df[~((self.df.split=='test')&(self.df.label=='ai_a_voice'))];self.check_changed(d,'missing a class')
    def test_duplicate_trace_rejected(self):
        d=self.df.copy();d.loc[1,'packet_file']=d.loc[0,'packet_file'];file=self.manifest.parent/'duplicates.csv';d.to_csv(file,index=False)
        with self.assertRaisesRegex(ValueError,'Duplicate packet'):load_manifest(file)

class EvaluationTests(unittest.TestCase):
    def test_group_bootstrap_paired_identity(self):
        y=['a','b','a','b'];g=['g1','g1','g2','g2']
        result=paired_group_intervals(y,y,y,g,['a','b'],4,100)
        self.assertEqual(result['gain_over_volume_95ci'],[0.,0.]);self.assertEqual(result['macro_f1_95ci'],[1.,1.])
    def test_network_plan_two_direction_delay(self):
        p=network_plan('lab','wan','lan','constrained')
        self.assertEqual(len(p),2)
        for row in p:self.assertIn('50ms',row['apply']);self.assertEqual(row['apply'][:4],['ip','netns','exec','lab'])
    def test_network_identifier_validation(self):
        with self.assertRaises(ValueError):network_plan('lab;rm','wan','lan','good')
    def test_network_refuses_foreign_qdisc(self):
        with patch('subprocess.check_output',return_value='[{"kind":"fq_codel","handle":"1:"}]'):
            with self.assertRaisesRegex(ValueError,'Existing'):network_change('lab','wan','lan','good')
    def test_network_rollback_after_failure(self):
        import subprocess
        with patch('subprocess.check_output',return_value='[{"kind":"noqueue"}]'),patch('subprocess.run') as run:
            run.side_effect=[None,subprocess.CalledProcessError(1,['tc']),None]
            with self.assertRaises(subprocess.CalledProcessError):network_change('lab','wan','lan','good')
            self.assertIn('del',run.call_args_list[-1].args[0])


class IntegrationContractTests(unittest.TestCase):
    def test_register_is_atomic_and_labels_from_plan(self):
        from genai_fingerprint.dataset import register_capture
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            packets=pd.DataFrame({'timestamp':[100+i for i in range(60)],'length':[80]*60,'direction':[1,-1]*30})
            write_pcap(packets,root/'fixture.pcap')
            pd.DataFrame([{'session_id':'s1','scenario_group':'g1','split':'train','planned_label':'ai_a_voice',
                           'mode':'voice','is_genai':1,'profile':'good'}]).to_csv(root/'plan.csv',index=False)
            kw=dict(worksheet=root/'plan.csv',session_id='s1',source=root/'fixture.pcap',device_ips=['192.0.2.10'],ready_time=100,
                    duration=60,date='2026-09-09',service='Fixture service',device_id='fixture',app_version='fixture',capture_drops=0,dataset=root/'data')
            result=register_capture(**kw)
            self.assertEqual(pd.read_csv(result['manifest']).label.iloc[0],'ai_a_voice')
            with self.assertRaisesRegex(ValueError,'already registered'):register_capture(**kw)
            self.assertEqual(len(pd.read_csv(result['manifest'])),1)
    def test_predict_rejects_real_synthetic_mixing(self):
        import joblib
        from genai_fingerprint.models import predict
        with tempfile.TemporaryDirectory() as td:
            model=Path(td)/'model.joblib';joblib.dump({'schema_version':1,'provenance':'synthetic'},model)
            with self.assertRaisesRegex(ValueError,'provenance mismatch'):predict(model,'does_not_exist.csv',0,60,'real')

if __name__=='__main__':unittest.main()
