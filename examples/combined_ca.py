import logging
import asyncio as aio
from ndn.app import NDNApp
from coalesce.coalesce_v1 import CaServer


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')

app = NDNApp()


async def after_start():
    ca = CaServer(app, '/example-ca')
    ca.register()
    await aio.sleep(0.1)
    print('CA is ready')


if __name__ == '__main__':
    app.run_forever(after_start=after_start())
