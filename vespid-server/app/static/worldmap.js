/**
 * ShieldNode Lightweight SVG World Map
 * Renders a simplified world map and colors countries by attack intensity.
 *
 * Usage:
 *   renderWorldMap(containerId, countryData)
 *   countryData = [ { code: 'US', count: 123 }, { code: 'CN', count: 456 }, ... ]
 */
(function() {
    'use strict';

    /* We fetch a standard world topojson at runtime from a CDN-free local embed.
       Instead, we use the Natural Earth simplified world GeoJSON converted to
       SVG paths. For bundle size, we use a curated set of ~180 country outlines
       stored as a separate JSON fetch from a well-known public domain source.

       Strategy: fetch a lightweight world-110m GeoJSON from unpkg (public domain
       Natural Earth data), parse it, and render SVG paths keyed by ISO code.
       This keeps our repo small while giving full coverage. */

    var MAP_DATA_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

    /* Cache parsed topology */
    var _cachedTopology = null;

    function renderWorldMap(containerId, countryData, options) {
        options = options || {};
        var container = document.getElementById(containerId);
        if (!container) return;

        container.innerHTML = '<div class="worldmap-loading">Loading map…</div>';

        var dataMap = {};
        var maxCount = 0;
        (countryData || []).forEach(function(item) {
            dataMap[item.code] = item.count;
            if (item.count > maxCount) maxCount = item.count;
        });

        if (_cachedTopology) {
            _drawMap(container, _cachedTopology, dataMap, maxCount, options);
            return;
        }

        fetch(MAP_DATA_URL)
            .then(function(r) { return r.json(); })
            .then(function(topo) {
                _cachedTopology = topo;
                _drawMap(container, topo, dataMap, maxCount, options);
            })
            .catch(function(err) {
                container.innerHTML = '<div class="worldmap-error">Map unavailable</div>';
                console.warn('WorldMap load failed:', err);
            });
    }

    /* TopoJSON → GeoJSON conversion (minimal, no library needed) */
    function _topoToGeo(topology) {
        var obj = topology.objects.countries || topology.objects[Object.keys(topology.objects)[0]];
        var arcs = topology.arcs;
        var transform = topology.transform;

        function decodeArc(arcIdx) {
            var reversed = arcIdx < 0;
            var arc = arcs[reversed ? ~arcIdx : arcIdx];
            var coords = [];
            var x = 0, y = 0;
            for (var i = 0; i < arc.length; i++) {
                x += arc[i][0];
                y += arc[i][1];
                var lon = x, lat = y;
                if (transform) {
                    lon = lon * transform.scale[0] + transform.translate[0];
                    lat = lat * transform.scale[1] + transform.translate[1];
                }
                coords.push([lon, lat]);
            }
            if (reversed) coords.reverse();
            return coords;
        }

        function ringToCoords(ring) {
            var coords = [];
            for (var i = 0; i < ring.length; i++) {
                var arcCoords = decodeArc(ring[i]);
                /* Skip first point of subsequent arcs (shared with previous) */
                if (i > 0) arcCoords = arcCoords.slice(1);
                coords = coords.concat(arcCoords);
            }
            return coords;
        }

        var features = [];
        var geometries = obj.geometries;
        for (var g = 0; g < geometries.length; g++) {
            var geom = geometries[g];
            var polys = [];

            if (geom.type === 'Polygon') {
                var rings = [];
                for (var r = 0; r < geom.arcs.length; r++) {
                    rings.push(ringToCoords(geom.arcs[r]));
                }
                polys.push(rings);
            } else if (geom.type === 'MultiPolygon') {
                for (var p = 0; p < geom.arcs.length; p++) {
                    var mRings = [];
                    for (var r2 = 0; r2 < geom.arcs[p].length; r2++) {
                        mRings.push(ringToCoords(geom.arcs[p][r2]));
                    }
                    polys.push(mRings);
                }
            }

            features.push({
                id: geom.id,
                properties: geom.properties || {},
                polys: polys
            });
        }
        return features;
    }

    /* ISO 3166-1 numeric → alpha-2 mapping (covers major countries) */
    var NUM_TO_ALPHA2 = {
        '004':'AF','008':'AL','012':'DZ','016':'AS','020':'AD','024':'AO','028':'AG',
        '031':'AZ','032':'AR','036':'AU','040':'AT','044':'BS','048':'BH','050':'BD',
        '051':'AM','056':'BE','060':'BM','064':'BT','068':'BO','070':'BA','072':'BW',
        '076':'BR','084':'BZ','090':'SB','092':'VG','096':'BN','100':'BG','104':'MM',
        '108':'BI','112':'BY','116':'KH','120':'CM','124':'CA','132':'CV','140':'CF',
        '144':'LK','148':'TD','152':'CL','156':'CN','158':'TW','170':'CO','174':'KM',
        '178':'CG','180':'CD','184':'CK','188':'CR','191':'HR','192':'CU','196':'CY',
        '203':'CZ','204':'BJ','208':'DK','212':'DM','214':'DO','218':'EC','222':'SV',
        '226':'GQ','231':'ET','232':'ER','233':'EE','234':'FO','242':'FJ','246':'FI',
        '250':'FR','254':'GF','258':'PF','260':'TF','262':'DJ','266':'GA','268':'GE',
        '270':'GM','275':'PS','276':'DE','288':'GH','296':'KI','300':'GR','304':'GL',
        '308':'GD','312':'GP','316':'GU','320':'GT','324':'GN','328':'GY','332':'HT',
        '336':'VA','340':'HN','344':'HK','348':'HU','352':'IS','356':'IN','360':'ID',
        '364':'IR','368':'IQ','372':'IE','376':'IL','380':'IT','384':'CI','388':'JM',
        '392':'JP','398':'KZ','400':'JO','404':'KE','408':'KP','410':'KR','414':'KW',
        '417':'KG','418':'LA','422':'LB','426':'LS','428':'LV','430':'LR','434':'LY',
        '438':'LI','440':'LT','442':'LU','450':'MG','454':'MW','458':'MY','462':'MV',
        '466':'ML','470':'MT','478':'MR','480':'MU','484':'MX','492':'MC','496':'MN',
        '498':'MD','499':'ME','504':'MA','508':'MZ','512':'OM','516':'NA','520':'NR',
        '524':'NP','528':'NL','540':'NC','548':'VU','554':'NZ','558':'NI','562':'NE',
        '566':'NG','570':'NU','578':'NO','580':'MP','583':'FM','584':'MH','585':'PW',
        '586':'PK','591':'PA','598':'PG','600':'PY','604':'PE','608':'PH','616':'PL',
        '620':'PT','624':'GW','626':'TL','630':'PR','634':'QA','642':'RO','643':'RU',
        '646':'RW','659':'KN','662':'LC','670':'VC','674':'SM','678':'ST','682':'SA',
        '686':'SN','688':'RS','690':'SC','694':'SL','702':'SG','703':'SK','704':'VN',
        '705':'SI','706':'SO','710':'ZA','716':'ZW','720':'YE','724':'ES','728':'SS',
        '729':'SD','740':'SR','748':'SZ','752':'SE','756':'CH','760':'SY','762':'TJ',
        '764':'TH','768':'TG','776':'TO','780':'TT','784':'AE','788':'TN','792':'TR',
        '795':'TM','798':'TV','800':'UG','804':'UA','807':'MK','818':'EG','826':'GB',
        '834':'TZ','840':'US','854':'BF','858':'UY','860':'UZ','862':'VE','876':'WF',
        '882':'WS','887':'YE','894':'ZM',
        /* Kosovo and others */
        '-99':'XK','010':'AQ'
    };

    /* Simple Mercator-like projection for SVG */
    function projectPoint(lon, lat, width, height) {
        /* Clamp latitude for Mercator */
        lat = Math.max(-85, Math.min(85, lat));
        var x = (lon + 180) / 360 * width;
        var latRad = lat * Math.PI / 180;
        var mercN = Math.log(Math.tan(Math.PI / 4 + latRad / 2));
        var y = height / 2 - (mercN / Math.PI) * (height / 2);
        return [x, y];
    }

    function polyToPath(rings, width, height) {
        var d = '';
        for (var r = 0; r < rings.length; r++) {
            var ring = rings[r];
            for (var i = 0; i < ring.length; i++) {
                /* Detect antimeridian crossing: if longitude jumps more than
                   180 degrees between consecutive points, split the path to
                   avoid a line drawn across the entire map. */
                if (i > 0) {
                    var dLon = Math.abs(ring[i][0] - ring[i-1][0]);
                    if (dLon > 180) {
                        /* Close current sub-path and start a new move */
                        d += 'Z';
                        var pt2 = projectPoint(ring[i][0], ring[i][1], width, height);
                        d += 'M' + pt2[0].toFixed(1) + ',' + pt2[1].toFixed(1);
                        continue;
                    }
                }
                var pt = projectPoint(ring[i][0], ring[i][1], width, height);
                d += (i === 0 ? 'M' : 'L') + pt[0].toFixed(1) + ',' + pt[1].toFixed(1);
            }
            d += 'Z';
        }
        return d;
    }

    function readCssVar(name, fallback) {
        if (typeof document === 'undefined') return fallback;
        var value = getComputedStyle(document.body).getPropertyValue(name).trim();
        return value || fallback;
    }

    function parseColor(value) {
        if (!value) return null;
        value = value.trim();
        /* hex */
        var hex = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(value);
        if (hex) {
            return {
                r: parseInt(hex[1], 16),
                g: parseInt(hex[2], 16),
                b: parseInt(hex[3], 16)
            };
        }
        /* rgb/rgba */
        var rgb = value.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
        if (rgb) {
            return {
                r: parseInt(rgb[1], 10),
                g: parseInt(rgb[2], 10),
                b: parseInt(rgb[3], 10)
            };
        }
        /* hsl/hsla - simple conversion for saturated theme colors */
        var hsl = value.match(/hsla?\((\d+),\s*(\d+)%,\s*(\d+)%/);
        if (hsl) {
            var h = parseInt(hsl[1], 10) / 360;
            var s = parseInt(hsl[2], 10) / 100;
            var l = parseInt(hsl[3], 10) / 100;
            var a = s * Math.min(l, 1 - l);
            var f = function(n) {
                var k = (n + h * 12) % 12;
                return Math.round((l - a * Math.max(-1, Math.min(k - 3, 9 - k, 1))) * 255);
            };
            return { r: f(0), g: f(8), b: f(4) };
        }
        return null;
    }

    function interpolateColor(c1, c2, t) {
        return {
            r: Math.round(c1.r + (c2.r - c1.r) * t),
            g: Math.round(c1.g + (c2.g - c1.g) * t),
            b: Math.round(c1.b + (c2.b - c1.b) * t)
        };
    }

    function intensityColor(count, maxCount) {
        if (!count || !maxCount) return null;
        /* Logarithmic scale for better visual distribution */
        var ratio = Math.log(count + 1) / Math.log(maxCount + 1);

        var low = parseColor(readCssVar('--worldmap-heat-low', '#3b82f6')) || { r: 59, g: 130, b: 246 };
        var midLow = parseColor(readCssVar('--worldmap-heat-mid-low', '#14b8a6')) || { r: 20, g: 184, b: 166 };
        var midHigh = parseColor(readCssVar('--worldmap-heat-mid-high', '#f97316')) || { r: 249, g: 115, b: 22 };
        var high = parseColor(readCssVar('--worldmap-heat-high', '#ef4444')) || { r: 239, g: 68, b: 68 };

        var c;
        if (ratio < 0.33) {
            c = interpolateColor(low, midLow, ratio / 0.33);
        } else if (ratio < 0.66) {
            c = interpolateColor(midLow, midHigh, (ratio - 0.33) / 0.33);
        } else {
            c = interpolateColor(midHigh, high, (ratio - 0.66) / 0.34);
        }
        return 'rgb(' + c.r + ',' + c.g + ',' + c.b + ')';
    }

    function _drawMap(container, topology, dataMap, maxCount, options) {
        var width = options.width || 900;
        var height = options.height || 460;

        var features = _topoToGeo(topology);

        var svgParts = [];
        svgParts.push('<svg class="worldmap-svg" viewBox="0 0 ' + width + ' ' + height +
            '" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet">');

        /* Background */
        svgParts.push('<rect width="' + width + '" height="' + height + '" fill="transparent"/>');

        for (var i = 0; i < features.length; i++) {
            var feat = features[i];
            /* Skip Antarctica — its polygon wraps the full longitude and
               renders as a distorted band under Mercator projection.
               ID can be 10, '010', or -99 depending on the dataset. */
            var fid = String(feat.id);
            if (fid === '10' || fid === '010' || fid === '-99') continue;
            var isoAlpha2 = NUM_TO_ALPHA2[fid] || '';
            var count = dataMap[isoAlpha2] || 0;
            var fill = count ? intensityColor(count, maxCount) : 'var(--worldmap-land)';
            var opacity = count ? '1' : '0.6';
            var stroke = 'var(--worldmap-border)';

            for (var p = 0; p < feat.polys.length; p++) {
                var d = polyToPath(feat.polys[p], width, height);
                if (!d) continue;
                svgParts.push('<path d="' + d + '" fill="' + fill + '" fill-opacity="' + opacity +
                    '" stroke="' + stroke + '" stroke-width="0.4"' +
                    ' data-country="' + isoAlpha2 + '"' +
                    (count ? ' data-count="' + count + '"' : '') +
                    '><title>' + (isoAlpha2 || 'Unknown') + (count ? ' — ' + count + ' events' : '') + '</title></path>');
            }
        }

        svgParts.push('</svg>');

        /* Legend */
        var legendHtml = '<div class="worldmap-legend">' +
            '<span class="worldmap-legend-label">Low</span>' +
            '<div class="worldmap-legend-gradient"></div>' +
            '<span class="worldmap-legend-label">High</span>' +
            '</div>';

        container.innerHTML = svgParts.join('') + legendHtml;

        /* Add hover interactivity */
        var svg = container.querySelector('svg');
        var tooltip = document.createElement('div');
        tooltip.className = 'worldmap-tooltip';
        tooltip.style.display = 'none';
        container.appendChild(tooltip);

        svg.addEventListener('mousemove', function(e) {
            var path = e.target.closest('path[data-country]');
            if (!path) { tooltip.style.display = 'none'; return; }
            var code = path.getAttribute('data-country');
            var cnt = path.getAttribute('data-count');
            if (!code) { tooltip.style.display = 'none'; return; }
            tooltip.innerHTML = '<strong>' + code + '</strong>' + (cnt ? ' — ' + cnt + ' events' : ' — no events');
            tooltip.style.display = 'block';
            var rect = container.getBoundingClientRect();
            tooltip.style.left = (e.clientX - rect.left + 12) + 'px';
            tooltip.style.top = (e.clientY - rect.top - 30) + 'px';
        });

        svg.addEventListener('mouseleave', function() {
            tooltip.style.display = 'none';
        });
    }

    /* Expose globally */
    window.renderWorldMap = renderWorldMap;
})();
