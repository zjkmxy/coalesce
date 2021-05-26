import os
import logging
import asyncio as aio
from ndn.encoding import Name
from ndn.app import NDNApp
from coalesce.coalesce_v1 import Requester

MASTER_KEY_PATH = './temp-master-key.dat'
CA_NAME = '/coal-exam/CA/example-ca'
DEVICE_IDENTITY = Name.from_str('/coal-exam/DEVICE/device1')
ROLE_NAMES = [Name.from_str('/coal-exam/ROLE/role1'),
              Name.from_str('/coal-exam/ROLE/role2')]
DATA_NAMES = [Name.from_str('/coal-exam/scope1/testApp'),
              Name.from_str('/coal-exam/scope2/testApp')]


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')


def main():
    app = NDNApp()
    signers = [None for _ in DATA_NAMES]

    for i, data_name in enumerate(DATA_NAMES):
        def wrapper(k):
            # Don't know why bu i cannot be directly used here
            @app.route(data_name)
            def on_interest(name, param, _app_param):
                nonlocal signers
                if signers[k] is None:
                    print('Not ready to serve yet.')
                    return
                content = f"Data in scope-{k+1}, signed by role-{k+1}'s key".encode()
                app.put_data(name, content=content, freshness_period=10000, signer=signers[k])
                print(f'>> I: {Name.to_str(name)}, {param}')
                print(f'<< D: {Name.to_str(name)}')
                print(f'Content: (size: {len(content)})')
                print()

        wrapper(i)

    async def after_start():
        nonlocal signers

        # Fetch CA's public key for demonstration.
        # Pre-shared in real-world scenario
        _, _, ca_pub_key = await app.express_interest(CA_NAME+'/KEY', can_be_prefix=True)
        ca_pub_key = bytes(ca_pub_key)

        # Create requester
        requester = Requester(app, DEVICE_IDENTITY, Name.from_str(CA_NAME), ca_pub_key, ROLE_NAMES)

        # Load existing master key
        if os.path.exists(MASTER_KEY_PATH):
            with open(MASTER_KEY_PATH, 'rb') as f:
                cat_data = f.read()
            requester.load_master_key(cat_data)
            new_cater = False
        else:
            requester.gen_master_key()
            new_cater = True

        # Register routes
        requester.register()
        await aio.sleep(0.1)
        if new_cater:
            print('Bootstrapping ...')
            await requester.bootstrap()
            await aio.sleep(0.1)
            cat_data = requester.save_master_key()
            with open(MASTER_KEY_PATH, 'wb') as f:
                f.write(cat_data)

        def on_renew():
            for j, _ in enumerate(DATA_NAMES):
                signers[j] = requester.signer(j)

        print('Register KEY rolling events ...')
        aio.create_task(requester.auto_renew(on_renew))
        print('Ready to serve.')
        print()

    app.run_forever(after_start=after_start())


if __name__ == '__main__':
    main()
