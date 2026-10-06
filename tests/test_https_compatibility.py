import json
from unittest.mock import Mock
import pytest
from src.dynamic.traffic.https_compatibility import classify_https_compatibility, validate_compatibility_metadata
from src.dynamic.traffic.mitmproxy_backend import MitmproxyCaptureBackend
from src.dynamic.traffic.service import DynamicTrafficService
from src.dynamic.traffic.models import CaptureSession, CaptureStatus
from src.dynamic.traffic.storage import TrafficStorage
from src.dynamic.report.generator import build_dynamic_analysis_report
from src.dynamic.report.models import DynamicReportError
from src.web.report_summary import build_report_summary

def evidence(*kinds):
 return {f'ref_{i}':{'observation':k,'package_name':'org.wikipedia','session_id':'s'} for i,k in enumerate(kinds)}

def classify(*kinds):
 rows=evidence(*kinds)
 return classify_https_compatibility('org.wikipedia','s',list(rows),rows)

@pytest.mark.parametrize('kinds,classification,state',[
 (['user_ca_identity_verified','real_https_transaction'],'https_available','available'),
 (['user_ca_identity_verified','app_trust_anchor_rejected'],'user_ca_not_trusted','unavailable'),
 (['app_trust_anchor_rejected'],'trust_scope_unknown','unknown'),
 (['trust_scope_unverified'],'trust_scope_unknown','unknown'),
 (['tls_interception_failed'],'tls_interception_unavailable','unavailable'),
 (['pinning_specific_signal'],'suspected_pinning','unavailable'),
 (['explicit_certificate_pinning_failure'],'confirmed_pinning','unavailable'),
 (['real_https_transaction'],'trust_scope_unknown','unknown'),
])
def test_classifications(kinds,classification,state):
 result=classify(*kinds)
 assert (result.classification,result.visibility)==(classification,state)
 assert validate_compatibility_metadata(result.to_dict(),'s')==result.to_dict()

@pytest.mark.parametrize('changes',[
 {'session_id':'other'}, {'package_name':'other'}, {'observation':'unknown'},
])
def test_evidence_ownership_and_vocabulary(changes):
 rows=evidence('app_trust_anchor_rejected');rows['ref_0'].update(changes)
 with pytest.raises(ValueError):classify_https_compatibility('org.wikipedia','s',list(rows),rows)


def test_empty_missing_and_unsafe_refs_rejected():
 for refs in [[],['missing'],['/tmp/token=SECRET']]:
  with pytest.raises(ValueError):classify_https_compatibility('org.wikipedia','s',refs,{})


def test_cannot_upgrade_or_strip_evidence():
 result=classify('user_ca_identity_verified','app_trust_anchor_rejected').to_dict()
 result.update(classification='confirmed_pinning',reason_code='PINNING_CONFIRMED')
 with pytest.raises(ValueError):validate_compatibility_metadata(result,'s')
 result=classify('trust_scope_unverified').to_dict();result.pop('evidence')
 with pytest.raises(ValueError):validate_compatibility_metadata(result,'s')


def test_trust_rejection_is_not_pinning():
 result=classify('user_ca_identity_verified','app_trust_anchor_rejected','pinning_specific_signal')
 assert result.classification=='user_ca_not_trusted'


def test_session_stop_storage_report_and_ui(tmp_path):
 b=MitmproxyCaptureBackend(executable_path='/missing',ca_directory=tmp_path)
 b.executable_path='/fake';b.is_alive=Mock(return_value=True);b.stop=Mock()
 service=DynamicTrafficService(backend=b,storage=TrafficStorage(str(tmp_path)))
 service.active_capture=CaptureSession(session_id='s',status=CaptureStatus.ACTIVE)
 rows=evidence('user_ca_identity_verified','app_trust_anchor_rejected')
 service.record_https_compatibility('org.wikipedia',list(rows),rows)
 summary=service.stop_capture()
 service.storage.save_traffic_json(tmp_path/'traffic.json','s',[],service.active_capture,summary)
 traffic=json.loads((tmp_path/'traffic.json').read_text())
 assert traffic['https_visibility']=='unavailable'
 report=build_dynamic_analysis_report('scan',{
  'session':{'session_id':'s','status':'ACTIVE','package_name':'org.wikipedia'},
  'exploration':{'status':'partial','screens_observed':1},'traffic':traffic})
 assert report['analysis_coverage']=='partial'
 assert report['traffic']['https_compatibility']['evidence_refs']==sorted(rows)
 notes=' '.join(build_report_summary(dynamic_report=report)['dynamic_summary']['coverage_limitations'])
 assert 'HTTPS visibility unavailable — application does not trust the current USER CA.' in notes
 assert 'pinning' not in notes.lower()
 assert 'absence of network activity' in notes


def test_ca_refresh_does_not_erase_app_outcome(tmp_path):
 from unittest.mock import patch
 b=MitmproxyCaptureBackend(executable_path='/missing',ca_directory=tmp_path);b.executable_path='/fake'
 service=DynamicTrafficService(backend=b,adb_bin='adb');service.active_capture=CaptureSession(session_id='s')
 rows=evidence('user_ca_identity_verified','app_trust_anchor_rejected')
 service.record_https_compatibility('org.wikipedia',list(rows),rows)
 with patch('src.dynamic.traffic.service.check_ca_trust',return_value=('unknown','ca_store_not_readable')):service.refresh_ca_trust('device')
 assert service.get_visibility_metadata()['https_reason']=='USER_CA_NOT_TRUSTED_BY_APP'
 b.https.backend_failed=True
 assert service.get_visibility_metadata()['https_reason']=='capture_backend_failure'

@pytest.mark.parametrize('reason,phrase',[
 ('CA_TRUST_SCOPE_UNKNOWN','trust scope is unknown'),
 ('TLS_INTERCEPTION_UNAVAILABLE','could not be established'),
 ('PINNING_SUSPECTED','not confirmed'),('PINNING_CONFIRMED','was evidenced')])
def test_report_wording(reason,phrase):
 report={'coverage':{'https_visibility':'unavailable'},'traffic':{'https_visibility_reason':reason}}
 assert phrase in ' '.join(build_report_summary(dynamic_report=report)['dynamic_summary']['coverage_limitations'])


def test_real_transaction_must_exist_before_available(tmp_path):
 b=MitmproxyCaptureBackend(executable_path='/missing',ca_directory=tmp_path)
 service=DynamicTrafficService(backend=b);service.active_capture=CaptureSession(session_id='s')
 rows=evidence('user_ca_identity_verified','real_https_transaction')
 with pytest.raises(ValueError,match='transaction evidence missing'):
  service.record_https_compatibility('org.wikipedia',list(rows),rows)
 assert not service.active_capture.metadata.get('https_compatibility')


def test_target_scope_enforced(tmp_path):
 service=DynamicTrafficService(backend=MitmproxyCaptureBackend(ca_directory=tmp_path))
 service.active_capture=CaptureSession(session_id='s',metadata={'target_package':'another.app'})
 rows=evidence('app_trust_anchor_rejected')
 with pytest.raises(ValueError,match='target mismatch'):
  service.record_https_compatibility('org.wikipedia',list(rows),rows)


def test_canonical_report_cannot_upgrade_rejection_to_available():
 result=classify('user_ca_identity_verified','app_trust_anchor_rejected').to_dict()
 artifacts={'session':{'session_id':'s','status':'ACTIVE','package_name':'org.wikipedia'},
  'exploration':{'status':'partial','screens_observed':1},
  'traffic':{'transactions':[],'http_visibility':'available','https_visibility':'available',
             'https_visibility_reason':'USER_CA_TRUSTED','https_compatibility':result}}
 with pytest.raises(DynamicReportError,match='contradicts'):
  build_dynamic_analysis_report('scan',artifacts)


def test_success_wording_stays_scoped():
 report={'coverage':{'https_visibility':'available'},'traffic':{'https_visibility_reason':'USER_CA_TRUSTED'}}
 notes=' '.join(build_report_summary(dynamic_report=report)['dynamic_summary']['coverage_limitations'])
 assert 'observed application only' in notes
 assert 'secure' not in notes.lower()
