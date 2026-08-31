from sast_platform.api import create_server


if __name__ == "__main__":
    server = create_server()
    print(f"SAST API listening on http://{server.server_address[0]}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
