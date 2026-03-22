from contextlib import asynccontextmanager

from fastapi import FastAPI,Query, Path, HTTPException
from typing import Annotated
from pydantic import BaseModel, Field
import redis.asyncio as aioredis

#for correct redis exit
@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await r.aclose()

app = FastAPI(lifespan = lifespan)
r = aioredis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
DHCP_HASH = "dhcp:mappings"

MAC_PATTERN = r"^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$"
IP_PATTERN = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

#Pydantic DHCP model with format validation patterns
class Mapping(BaseModel):
    mac: str = Field(title="MAC", description="XX:XX:XX:XX:XX:XX format", pattern=MAC_PATTERN)
    ip: str = Field(title="IP", description="X.X.X.X format", pattern=IP_PATTERN)

#Adds a new mapping {mac: ip}
@app.post("/mappings")
async def post_mapping(mapping: Mapping):
    if await r.hexists(DHCP_HASH, mapping.mac):
        raise HTTPException(status_code=409, detail="MAC-key is already exists")
    await r.hset(DHCP_HASH, mapping.mac, mapping.ip)
    return mapping

#Gets all mappings (or a single mapping by optional MAC query-parameter)
@app.get("/mappings")
async def get_mappings(mac: str|None = Query(None, pattern=MAC_PATTERN)):
    if mac:
        ip = await r.hget(DHCP_HASH, mac)
        if not ip:
            raise HTTPException(status_code=404, detail="Mapping not found")
        return {mac: ip}
    return await r.hgetall(DHCP_HASH)

#Gets IP by MAC path-parameter
@app.get("/mappings/{mac}")
async def get_ip(mac: Annotated[str, Path(pattern=MAC_PATTERN)]):
    ip = await r.hget(DHCP_HASH, mac)
    if not ip:
            raise HTTPException(status_code=404, detail="Mapping not found")
    return {mac: ip}

#Updates a mapping by MAC path-parameter
@app.put("/mappings/{mac}")
async def put_mapping(mac: Annotated[str, Path(pattern=MAC_PATTERN)], ip: Annotated[str, Query(pattern=IP_PATTERN)]):
    if not await r.hexists(DHCP_HASH, mac):
        raise HTTPException(status_code=404, detail="MAC not found. Please, use post.")
    await r.hset(DHCP_HASH, mac, ip)
    return {mac: ip}

#Deletes a mapping by MAC path-parameter
@app.delete("/mappings/{mac}")
async def delete_mapping(mac: Annotated[str, Path(pattern=MAC_PATTERN)]):
    if not await r.hdel(DHCP_HASH, mac):
        raise HTTPException(status_code=404, detail="MAC is not exists.")
    return {"message": "mapping deleted"}