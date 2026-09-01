import sys
sys.path.insert(0, '/app')
import asyncio, time
from main import _execute_on_device

async def test():
    # Show command
    start = time.time()
    r = await _execute_on_device('switch', 'show interfaces status gi5')
    print(f'Show: {time.time()-start:.1f}s, len={len(r["output"])}')
    
    # Config command
    start = time.time()
    r2 = await _execute_on_device('switch', 'configure terminal\ninterface gi5\nshutdown\nend')
    print(f'Config: {time.time()-start:.1f}s, len={len(r2["output"])}')
    print(f'Output: {r2["output"][:200]}')
    
    await asyncio.sleep(2)
    
    # Verify
    r3 = await _execute_on_device('switch', 'show interfaces status gi5')
    for line in r3['output'].splitlines():
        cols = line.split()
        if cols and cols[0] == 'gi5':
            print(f'gi5 status: {cols[6] if len(cols) > 6 else "N/A"}')
    
    # Restore
    start = time.time()
    r4 = await _execute_on_device('switch', 'configure terminal\ninterface gi5\nno shutdown\nend')
    print(f'Restore: {time.time()-start:.1f}s, len={len(r4["output"])}')
    
    await asyncio.sleep(2)
    
    # Verify restore
    r5 = await _execute_on_device('switch', 'show interfaces status gi5')
    for line in r5['output'].splitlines():
        cols = line.split()
        if cols and cols[0] == 'gi5':
            print(f'gi5 status: {cols[6] if len(cols) > 6 else "N/A"}')

asyncio.run(test())
