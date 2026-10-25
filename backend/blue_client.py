import httpx


class BlueServiceClient:
    def __init__(self, base_url, service_token, transport=None):
        self.base_url = base_url.rstrip("/")
        self.service_token = service_token
        self.transport = transport

    async def read_resource(self, resource_id):
        async with httpx.AsyncClient(
            base_url=self.base_url,
            transport=self.transport,
            timeout=5.0,
        ) as client:
            return await client.get(
                f"/internal/resources/{resource_id}",
                headers={"Authorization": f"Bearer {self.service_token}"},
            )
