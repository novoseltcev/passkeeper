INSERT INTO accounts (uuid, login, password_hash, passphrase_hash) VALUES
    ('62822284-5a2a-4a5d-b66e-12d09e0fe79c', 'test@example.com', '1234', '4567'),
    ('08108e22-a2d8-4ce7-abbb-13d91dacc758', 'test@test.com', '4321', '7654');

INSERT INTO sessions (uuid, account_uuid, created_at, expires_at) VALUES
    ('b3055e06-9300-4d6a-9df1-b95e6fefc916', '62822284-5a2a-4a5d-b66e-12d09e0fe79c', now(), now() + interval '1 hour'),
    ('e065b8b6-6d1e-4d1b-bf58-52b0df58f147', '62822284-5a2a-4a5d-b66e-12d09e0fe79c', now(), now());

INSERT INTO secrets (uuid, owner_uuid, name, type, encrypted_data, created_at) VALUES
    ('a6a3097b-7b03-4f3c-9686-7264a163b34d', '62822284-5a2a-4a5d-b66e-12d09e0fe79c', 'some', 2, decode('deff1234', 'hex'), now()),
    ('fd537d2d-a926-4027-b76f-0148a384a7b1', '62822284-5a2a-4a5d-b66e-12d09e0fe79c', 'some1', 1, decode('abc1', 'hex'), now()),
    ('87c7b7f3-fb64-4206-849c-a40f98665961', '62822284-5a2a-4a5d-b66e-12d09e0fe79c', 'some', 3, decode('1234', 'hex'), now()),
    ('e58bbd83-6068-4bfd-a769-36b2962c759a', '08108e22-a2d8-4ce7-abbb-13d91dacc758', 'some', 4, decode('0001', 'hex'), now());
