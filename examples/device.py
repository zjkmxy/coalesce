import os
import logging
import asyncio as aio
from ndn.encoding import Name
from ndn.app import NDNApp
from coalesce.butterfly import Caterpillar
from coalesce.coalesce_v1 import Requester

CATERPILLAR_PATH = './temp-caterpillar.dat'

logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')


def main():
    app = NDNApp()
    signer = None

    @app.route('/example-device/testApp')
    def on_interest(name, param, _app_param):
        if signer is None:
            print('Not ready to serve yet.')
            return
        content = "Hello, world!".encode()
        app.put_data(name, content=content, freshness_period=10000, signer=signer)
        print(f'>> I: {Name.to_str(name)}, {param}')
        print(f'<< D: {Name.to_str(name)}')
        print(f'Content: (size: {len(content)})')
        print()

    async def after_start():
        nonlocal signer

        if os.path.exists(CATERPILLAR_PATH):
            with open(CATERPILLAR_PATH, 'rb') as f:
                cat_data = f.read()
            caterpillar = Caterpillar.load_prv(cat_data)
            new_cater = False
        else:
            caterpillar = Caterpillar.generate()
            with open(CATERPILLAR_PATH, 'wb') as f:
                f.write(caterpillar.save_prv())
            new_cater = True

        requester = Requester(app, caterpillar, '/example-device', '/example-ca')
        requester.register()
        await aio.sleep(0.1)
        if new_cater:
            print('Bootstrapping ...')
            await requester.bootstrap()
            await aio.sleep(0.1)
        print('Fetching certificates ...')
        await requester.renew()
        signer = requester.signer()
        print('Ready to serve.')
        print()

    app.run_forever(after_start=after_start())


if __name__ == '__main__':
    main()
