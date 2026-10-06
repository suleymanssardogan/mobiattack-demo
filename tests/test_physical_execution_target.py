"""Physical target adapter tests use mocked ADB only; no device/proxy modifications."""
import json
from unittest.mock import Mock, patch
import pytest
from src.dynamic.runtime.execution_target import (
 AdbTargetAdapter, PhysicalDeviceTargetAdapter, ExecutionTarget, TargetType,
 select_transport, save_target, load_target, environment_summary)
from src.android_runtime_launcher import launch_android_app, AndroidRuntimeError

SERIAL='physical-private-123'
def query(args,serial=None):
 if args==['devices']:return 0,'List of devices attached\n'+SERIAL+' device\nemulator-5554 device',''
 if args[:2]==['shell','which']:return 0,'\n'.join('/system/bin/'+x for x in args[2:]),''
 props={'ro.kernel.qemu':'0','ro.product.cpu.abilist':'arm64-v8a','ro.build.version.sdk':'35','ro.build.characteristics':'phone'}
 return 0,props.get(args[-1],''),''


def test_physical_descriptor_capabilities_and_no_proxy():
 target=PhysicalDeviceTargetAdapter().describe(SERIAL,query)
 assert target.target_type==TargetType.PHYSICAL_DEVICE
 assert target.require_transport(SERIAL)==SERIAL
 assert target.api_level==35 and target.abis==['arm64-v8a']
 assert target.proxy_context=={}
 for key in ('app_install','app_launch','pid_observation','foreground_observation','ui_automation'):
  assert target.capabilities[key].state=='available'
  assert target.capabilities[key].reason=='TOOL_AVAILABLE'
 for key in ('traffic_capture','proxy_configuration','http_capture','https_capture'):
  assert target.capabilities[key].state=='unavailable'
 assert target.capabilities['host_reachability'].state=='unknown'

@pytest.mark.parametrize('state,reason',[('offline','DEVICE_OFFLINE'),('unauthorized','DEVICE_UNAUTHORIZED')])
def test_bad_transport_rejected_without_properties(state,reason):
 q=Mock(return_value=(0,f'List of devices attached\n{SERIAL} {state}',''))
 with pytest.raises(ValueError,match=reason):PhysicalDeviceTargetAdapter().describe(SERIAL,q)
 assert q.call_count==1


def test_multiple_devices_require_selection():
 with pytest.raises(ValueError,match='MULTIPLE_DEVICES'):select_transport([(SERIAL,'device'),('other','device')])
 assert select_transport([('other','device'),(SERIAL,'device')],SERIAL)==SERIAL

@pytest.mark.parametrize('qemu,chars',[('', 'phone'),('0','default')])
def test_normal_physical_property_variants(qemu,chars):
 def q(args,serial=None):
  if args[-1]=='ro.kernel.qemu':return 0,qemu,''
  if args[-1]=='ro.build.characteristics':return 0,chars,''
  return query(args,serial)
 assert AdbTargetAdapter().describe('127.0.0.1:9999',q).target_type==TargetType.PHYSICAL_DEVICE


def test_missing_properties_stay_unknown():
 assert AdbTargetAdapter().describe(SERIAL,lambda *a,**k:(1,'','')).target_type==TargetType.UNKNOWN
 with pytest.raises(ValueError):PhysicalDeviceTargetAdapter().describe(SERIAL,lambda *a,**k:(1,'',''))


def test_emulator_not_accepted_as_physical():
 def q(args,serial=None):
  if args[-1]=='ro.kernel.qemu':return 0,'1',''
  return query(args,serial)
 with pytest.raises(ValueError,match='TARGET_TYPE_UNVERIFIED'):PhysicalDeviceTargetAdapter().describe(SERIAL,q)
 emulator=AdbTargetAdapter().describe('emulator-5554',q)
 assert emulator.target_type==TargetType.EMULATOR
 assert emulator.proxy_context['host']=='10.0.2.2'
 assert emulator.capabilities['traffic_capture'].state=='unknown'


def test_physical_launch_uses_existing_flow_and_persistence(tmp_path):
 target=ExecutionTarget.selected(SERIAL,TargetType.PHYSICAL_DEVICE,availability='available')
 with patch('src.android_runtime_launcher.resolve_adb_executable',return_value='adb'), \
      patch('src.android_runtime_launcher.select_target_device',return_value=SERIAL), \
      patch('src.dynamic.preflight.device_check.run_adb_cmd',side_effect=lambda binary,args,serial=None,**kw:query(args,serial)), \
      patch('src.android_runtime_launcher.install_apk',return_value={'success':True}) as install, \
      patch('src.android_runtime_launcher.launch_activity',return_value={'success':True}) as launch, \
      patch('src.android_runtime_launcher.query_process_pid',return_value=42), \
      patch('src.android_runtime_launcher.get_current_activity',return_value={'observed_package':'training.app','observed_activity':'training.app.Main'}):
  result=launch_android_app(tmp_path/'app.apk','training.app','.Main',execution_target=target,run_dir=tmp_path)
 assert install.call_args.kwargs['serial']==SERIAL
 assert launch.call_args.kwargs['serial']==SERIAL
 assert result['runtime']['foreground_verified']
 loaded=load_target(tmp_path)
 assert loaded.target_type==TargetType.PHYSICAL_DEVICE
 assert loaded.capabilities['app_install'].reason=='OBSERVED'
 assert loaded.capabilities['proxy_configuration'].state=='unavailable'
 assert SERIAL not in json.dumps(environment_summary(loaded))


def test_wrong_type_prevents_install():
 target=ExecutionTarget.selected(SERIAL,TargetType.PHYSICAL_DEVICE,availability='available')
 with patch('src.android_runtime_launcher.resolve_adb_executable',return_value='adb'), \
      patch('src.android_runtime_launcher.select_target_device',return_value=SERIAL), \
      patch('src.dynamic.preflight.device_check.run_adb_cmd',return_value=(1,'','')), \
      patch('src.android_runtime_launcher.install_apk') as install:
  with pytest.raises(AndroidRuntimeError):launch_android_app(None,'training.app','.Main',execution_target=target)
 install.assert_not_called()


def test_physical_ui_pipeline_does_not_attempt_proxy(tmp_path):
 from src.orchestration.exploration import _wire_dynamic_exploration
 root=tmp_path/'dynamic';root.mkdir()
 target=PhysicalDeviceTargetAdapter().describe(SERIAL,query);save_target(tmp_path,target)
 (root/'preflight_result.json').write_text(json.dumps({'status':'PASS','device':{'serial':SERIAL},'application':{'package_name':'training.app'}}))
 (root/'session.json').write_text(json.dumps({'session_id':'s','status':'ACTIVE','device_serial':SERIAL}))
 result=Mock();result.screens_observed=1;result.actions_succeeded=0;result.to_dict.return_value={'screens_observed':1}
 run=Mock(return_value=result)
 with patch('src.dynamic.preflight.device_check.run_adb_cmd',side_effect=lambda binary,args,**kw:query(args)), \
      patch('src.android_runtime_launcher.resolve_adb_executable',return_value='adb'), \
      patch('src.dynamic.traffic.service.DynamicTrafficService.check_readiness') as readiness, \
      patch('src.dynamic.traffic.service.DynamicTrafficService.start_capture') as capture:
  returned=_wire_dynamic_exploration(tmp_path,'training.app',adb_serial=SERIAL,run_exploration=run,
    _update_scan_state_dynamic_stage=Mock(),_emit_progress=Mock(),_wire_api_correlation=Mock(),_wire_dynamic_analysis_report=Mock(return_value=None))
 assert returned is result
 readiness.assert_not_called();capture.assert_not_called()
 assert run.call_args.kwargs['executor'].serial==SERIAL
 assert run.call_args.kwargs['runtime_observer'].serial==SERIAL
 assert run.call_args.kwargs['traffic_service'] is None
 traffic=json.loads((root/'traffic.json').read_text())
 assert traffic['http_visibility']=='unavailable'
 assert traffic['http_visibility_reason']=='physical_device_traffic_not_supported'
 assert load_target(tmp_path).capabilities['proxy_configuration'].state=='unavailable'


def test_adapter_requires_explicit_selection():
 q=Mock()
 with pytest.raises(ValueError,match='TARGET_SELECTION_REQUIRED'):PhysicalDeviceTargetAdapter().describe(None,q)
 q.assert_not_called()


def test_loopback_transport_is_not_emulator_evidence():
 from src.dynamic.preflight.device_check import _detect_is_emulator
 with patch('src.dynamic.preflight.device_check.run_adb_cmd',return_value=(0,'','')):
  assert not _detect_is_emulator('adb','127.0.0.1:9999')


def test_preflight_auto_classifies_physical_without_new_pipeline():
 from src.dynamic.preflight.service import DynamicPreflightService
 from src.dynamic.preflight.models import DeviceInfo, ApplicationInfo
 with patch('src.dynamic.preflight.service.find_adb_binary',return_value='adb'), \
      patch('src.dynamic.preflight.service.check_connected_device',return_value=(DeviceInfo(connected=True,serial=SERIAL,state='device'),None,None)), \
      patch('src.dynamic.preflight.service.run_adb_cmd',side_effect=lambda binary,args,serial=None,**kw:query(args,serial)), \
      patch('src.dynamic.preflight.service.inspect_package',return_value=(ApplicationInfo(package_name='training.app',installed=False),None,None)):
  result=DynamicPreflightService(adb_bin='adb').run_preflight('training.app',target_serial=SERIAL,auto_install=False)
 assert result.execution_target['target_type']==TargetType.PHYSICAL_DEVICE
 assert result.execution_target['proxy_context']=={}


def test_physical_target_rejects_emulator_proxy_context():
 with pytest.raises(ValueError,match='proxy configuration is unsupported'):
  ExecutionTarget.selected(SERIAL,TargetType.PHYSICAL_DEVICE,
      proxy_context={'host':'10.0.2.2','source':'emulator_adapter_configuration'})
