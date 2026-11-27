#!/usr/bin/env python3
"""Convert one pinned Natural Earth public-domain GeoJSON into local SVG geometry."""
import argparse
import hashlib
import json
import math
import re
from pathlib import Path

SOURCE_SHA256 = '6866c877d39cba9c357620878839b336d569f8c662d3cfab4cb1dbe2d39c977f'


def project(lon, lat):
    # Static Plate Carrée projection, left map area only. The UI summary card
    # is intentionally outside it and never has geographic coordinates.
    if not (math.isfinite(lon) and math.isfinite(lat) and -180.0001 <= lon <= 180.0001 and -90 <= lat <= 90):
        raise ValueError('coordinate outside earth')
    return [round(17 + (lon + 180) * 1.86, 1), round(23 + (85 - lat) * 2, 1)]


def convert(raw):
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        raise ValueError('expected Natural Earth 5.1.2 source bytes')
    land, anchors = [], {}
    for feature in json.loads(raw)['features']:
        props = feature['properties']
        if props['ADM0_A3'] == 'ATA':
            continue
        code = props.get('ISO_A2_EH')
        if not isinstance(code, str) or not re.fullmatch(r'[A-Z]{2}', code):
            code = None
        geometry = feature['geometry']
        coords = geometry['coordinates']
        polygons = [coords] if geometry['type'] == 'Polygon' else coords
        paths = []
        for poly in polygons:
            for ring in poly:
                pts = [project(*coord[:2]) for coord in ring]
                pairs = ['{},{}'.format(*pt) for i, pt in enumerate(pts) if i==0 or pt!=pts[i-1]]
                if len(set(pairs))>=3:
                    paths.append('M'+'L'.join(pairs)+'Z')
        if paths:
            land.append([code, ''.join(paths)])
        if code and code not in anchors and -170 <= props['LABEL_X'] <= 180 and -59 <= props['LABEL_Y'] <= 85:
            anchors[code] = project(props['LABEL_X'], props['LABEL_Y'])
    return {'schema_version':1, 'source':'Natural Earth 5.1.2 / admin 0 countries 1:110m', 'land':land,
            'anchors':dict(sorted(anchors.items()))}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('geojson',type=Path)
    p.add_argument('output',type=Path)
    a=p.parse_args()
    a.output.write_text(json.dumps(convert(a.geojson.read_bytes()),separators=(',',':'))+'\n')


if __name__=='__main__':
    main()
