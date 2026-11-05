#!/usr/bin/env python3
"""Exercise the actual Swift protocol helpers with CryptoKit, no simulator or production private keys."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[1]
source=(root/'DoorKey/DoorKeyApp.swift').read_text()
model=source[source.index('struct WalletKey:'):source.index('enum ManagerError:')]
integers=source[source.index('extension Data {'):source.index('final class DoorBluetooth:')]
error=source[source.index('enum DemoError:'):source.index('extension Data {')]
trust=(root/'DoorKey/TrustConfig.swift').read_text()
tests=(root/'tests/protocol-tests.swift').read_text()
with tempfile.TemporaryDirectory(prefix='doorkey-swift-') as folder:
 file=Path(folder)/'main.swift'
 file.write_text('import Foundation\nimport CryptoKit\n'+trust+'\n'+error+'\n'+integers+'\n'+model+'\n'+tests)
 subprocess.run(['xcrun','swiftc','-module-cache-path',folder+'/cache',str(file),'-o',folder+'/tests'],check=True)
 subprocess.run([folder+'/tests'],check=True)
