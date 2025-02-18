var graph = {},
    selected = {},
    highlighted = null,
    isIE = false,
    config = {},
    remoteDocs = {},
    z_type = 'zone';

function displayErrorMessage(message) {
    document.getElementById("errorMessage").innerHTML = message;
}

$(function () {
    resize();

    isIE = !!navigator.userAgent.match(/Trident/g) || !!navigator.userAgent.match(/MSIE/g);

    if (navigator.userAgent.toLowerCase().indexOf('firefox') > -1) {
        $('body').addClass('firefox');
    }

    var zoneVal = qs("zone");
    if (!zoneVal) {
        displayErrorMessage("A zone must be provided.");
        return;
    }

    config['title'] = zoneVal + " Certificate Map";
    config['constraints'] = [];
    config['constraints'][0] = {};
    config['constraints'][0]['x'] = 0.5;
    config['constraints'][0]['y'] = 0.5;
    config['constraints'][0]['type'] = 'position';
    config['constraints'][0]['has'] = {};
    config['constraints'][0]['has']['type'] = zoneVal;
    config['graph'] = {}
    config['graph']['charge'] = -400;
    config['graph']['linkDistance'] = 150;
    config['graph']['height'] = document.getElementById("graph").clientHeight;
    config['graph']['numColors'] = 1;
    config['graph']['ticksWithoutCollision'] = 100;
    config['graph']['labelMargin'] = {};
    config['graph']['labelMargin']['top'] = 2;
    config['graph']['labelMargin']['left'] = 3;
    config['graph']['labelMargin']['bottom'] = 2;
    config['graph']['labelMargin']['right'] = 3;
    config['graph']['labelPadding'] = {};
    config['graph']['labelPadding']['top'] = 2;
    config['graph']['labelPadding']['left'] = 3;
    config['graph']['labelPadding']['bottom'] = 2;
    config['graph']['labelPadding']['right'] = 3;

    var searchForm = document.getElementById("searchForm");
    var searchButton = document.getElementById("searchButton");
    searchForm.addEventListener("submit", function (evt) { evt.preventDefault(); doSearch(); return false; });
    searchButton.addEventListener("click", doSearch);

    var reloadForm = document.getElementById("reloadForm");
    var reloadButton = document.getElementById("reloadButton");
    reloadForm.addEventListener("submit", function (evt) { evt.preventDefault(); doReload(); return false; });
    reloadButton.addEventListener("click", doReload);

    var xmlhttp = new XMLHttpRequest();
    var url;
    if (zoneVal) {
        url = "/api/v1.0/cert_graphs/" + zoneVal;
    }

    xmlhttp.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            let data = JSON.parse(this.responseText);
            if (data == null) {
                displayErrorMessage('No data!');
                return;
            }
            graph.data = data;
            drawGraph();
        } else if (this.readyState === 4 && this.status !== 200) {
            displayErrorMessage("Error: Could not fetch data!");
        }
    };
    xmlhttp.open("GET", url, true);
    xmlhttp.send();

    $('#docs-close').on('click', function () {
        deselectObject();
        return false;
    });

    $(document).on('click', '.select-object', function () {
        var obj = graph.data[$(this).data('name')];
        if (obj) {
            selectObject(obj);
        }
        return false;
    });

    $(window).on('resize', resize);
});

function find_by_name(arr, value) {
    var result = arr.filter(function (obj) { return obj.id === value; })
    return result ? result[0] : null;
}

function drawGraph(z_type) {
    $('#graph').empty();

    graph.margin = {
        top: 65,
        right: 20,
        bottom: 20,
        left: 20
    };

    var display = $('#graph').css('display');
    $('#graph')
        .css('display', 'block')
        .css('height', config.graph.height + 'px');
    graph.width = $('#graph').width() - graph.margin.left - graph.margin.right;
    graph.height = $('#graph').height() - graph.margin.top - graph.margin.bottom;
    $('#graph').css('display', display);

    for (let entry in graph.data.nodes) {
        let obj = graph.data.nodes[entry];
        obj.positionConstraints = [];
        obj.linkStrength = 1;

        config.constraints.forEach(function (c) {
            for (var k in c.has) {
                if (c.has[k] !== obj[k]) {
                    return true;
                }
            }

            switch (c.type) {
                case 'position':
                    obj.positionConstraints.push({
                        weight: c.weight,
                        x: c.x * graph.width,
                        y: c.y * graph.height
                    });
                    break;

                case 'linkStrength':
                    obj.linkStrength *= c.strength;
                    break;
            }
            return false;
        });
    }

    graph.links = graph.data.links;

    graph.categories = {};
    for (let entry in graph.data.nodes) {
        if (graph.data.nodes[entry].type === "certificate") {
            let obj = graph.data.nodes[entry],
                key = graph.data.nodes[entry].id,
                cat = graph.categories[key];

            let data_type = obj.sources[0];
            if (obj.sources.length === 2) {
                data_type = "ct_logs";
            }

            obj.categoryKey = key;
            if (!cat) {
                cat = graph.categories[key] = {
                    key: key,
                    type: obj.type,
                    typeName: obj.type,
                    group: key,
                    data_type: data_type,
                    count: 0
                };
            }
            cat.count++;
        } else {
            let id = graph.data.nodes[entry].id;
            let key = id;
            let levels = id.split('.');
            if (levels.length > 1) {
                key = levels[levels.length - 2] + '.' + levels[levels.length - 1];
            }

            let obj = graph.data.nodes[entry];
            obj.categoryKey = key;

            let cat = graph.categories[key];
            if (!cat) {
                cat = graph.categories[key] = {
                    key: key,
                    type: 'domains',
                    typeName: 'domains',
                    group: key,
                    data_type: 'domains',
                    count: 0
                };
            }
            cat.count++;
        }
    }

    graph.categoryKeys = Object.keys(graph.categories);

    graph.colors = []
    for (let i = 1; i < Object.keys(graph.categories).length + 2; i++) {
        graph.colors.push(d3.interpolateSpectral(i / Object.keys(graph.categories).length));
    }


    function getColorScale(darkness) {
        return d3.scaleOrdinal()
            .domain(graph.categoryKeys)
            .range(graph.colors.map(function (c) {
                return d3.hsl(c).darker(darkness).toString();
            }));
    }

    graph.strokeColor = getColorScale(0.7);
    graph.fillColor = getColorScale(-0.1);

    graph.simulation = d3.forceSimulation()
        .force("link", d3.forceLink().id(function (d) { return d.id; }))
        .force("charge", d3.forceManyBody())
        .force("center", d3.forceCenter(graph.width / 2, graph.height / 2));

    graph.simulation
        .nodes(graph.data.nodes)
        .on("tick", tick);

    graph.simulation.force("link").links(graph.links);

    graph.svg = d3.select('#graph').append('svg')
        .attr('width', graph.width + graph.margin.left + graph.margin.right)
        .attr('height', graph.height + graph.margin.top + graph.margin.bottom)
        .attr('id', 'graph-svg')
        .append('g')
        .attr('transform', 'translate(' + graph.margin.left + ',' + graph.margin.top + ')');

    var glow = graph.svg.append('filter')
        .attr('x', '-50%')
        .attr('y', '-50%')
        .attr('width', '200%')
        .attr('height', '200%')
        .attr('id', 'blue-glow');

    glow.append('feColorMatrix')
        .attr('type', 'matrix')
        .attr('values', '0 0 0 0  0 '
            + '0 0 0 0  0 '
            + '0 0 0 0  .7 '
            + '0 0 0 1  0 ');

    glow.append('feGaussianBlur')
        .attr('stdDeviation', 3)
        .attr('result', 'coloredBlur');

    glow.append('feMerge').selectAll('feMergeNode')
        .data(['coloredBlur', 'SourceGraphic'])
        .enter().append('feMergeNode')
        .attr('in', String);


    d3.select('#graph').call(d3.zoom().on('zoom', doZoom));

    graph.line = graph.svg.append('g').selectAll('.link')
        .data(graph.links)
        .enter().append('line')
        .attr('class', 'link');

    graph.draggedThreshold = d3.scaleLinear()
        .domain([0, 0.1])
        .range([5, 25])
        .clamp(true);

    function dragged(d) {
        var threshold = graph.draggedThreshold(graph.simulation.alpha()),
            dx = d.oldX - d.x,
            dy = d.oldY - d.y;
        if (Math.abs(dx) >= threshold || Math.abs(dy) >= threshold) {
            d.dragged = true;
        }
        return d.dragged;
    }

    graph.drag = d3.drag()
        .subject(function (d) { return d; })
        .on('start', function (event, d) {
            if (!event.active) graph.simulation.alphaTarget(0.3).restart();
            d.oldX = d.x;
            d.oldY = d.y;
            d.dragged = false;
            d.fixed |= 2;
        })
        .on('drag', function (event, d) {
            d.x = event.x;
            d.y = event.y;
            if (dragged(d)) {
                if (!graph.simulation.alpha()) {
                    graph.simulation.alpha(.025);
                }
            }
        })
        .on('end', function (event, d) {
            if (!event.active) graph.simulation.alphaTarget(0);
            if (!dragged(d)) {
                selectObject(d, this);
            }
            d.fixed &= ~6;
        });

    $('#graph-container').on('click', function (e) {
        if (!$(e.target).closest('.node').length) {
            deselectObject();
        }
    });

    graph.node = graph.svg.selectAll('.node')
        .data(graph.simulation.nodes())
        .enter().append('g')
        .attr('class', 'node')
        .call(graph.drag)
        .on('mouseover', function (event, d) {
            if (!selected.obj) {
                if (graph.mouseoutTimeout) {
                    clearTimeout(graph.mouseoutTimeout);
                    graph.mouseoutTimeout = null;
                }
                highlightObject(event, d);
            }
        })
        .on('mouseout', function (event, d) {
            if (!selected.obj) {
                if (graph.mouseoutTimeout) {
                    clearTimeout(graph.mouseoutTimeout);
                    graph.mouseoutTimeout = null;
                }
                graph.mouseoutTimeout = setTimeout(function () {
                    highlightObject(null, null);
                }, 300);
            }
        });

    graph.nodeRect = graph.node.append('rect')
        .attr('rx', 5)
        .attr('ry', 5)
        .attr('stroke', function (d) {
            return graph.strokeColor(d.categoryKey);
        })
        .attr('fill', function (d) {
            return graph.fillColor(d.categoryKey);
        })
        .attr('width', 120)
        .attr('height', 30);

    graph.node.each(function (d) {
        var node = d3.select(this),
            lines = wrap(d.id),
            ddy = 1.1,
            dy = -ddy * lines.length / 2 + .5;

        lines.forEach(function (line) {
            node.append('text')
                .text(line)
                .attr('dy', dy + 'em');
            dy += ddy;
        });
    });

    setTimeout(function () {
        graph.node.each(function (d) {
            var node = d3.select(this),
                text = node.selectAll('text'),
                bounds = {},
                first = true;

            text.each(function () {
                var box = this.getBBox();
                if (first || box.x < bounds.x1) {
                    bounds.x1 = box.x;
                }
                if (first || box.y < bounds.y1) {
                    bounds.y1 = box.y;
                }
                if (first || box.x + box.width > bounds.x2) {
                    bounds.x2 = box.x + box.width;
                }
                if (first || box.y + box.height > bounds.y2) {
                    bounds.y2 = box.y + box.height;
                }
                first = false;
            }).attr('text-anchor', 'middle');

            var padding = config.graph.labelPadding,
                margin = config.graph.labelMargin,
                oldWidth = bounds.x2 - bounds.x1;

            bounds.x1 -= oldWidth / 2;
            bounds.x2 -= oldWidth / 2;

            bounds.x1 -= padding.left;
            bounds.y1 -= padding.top;
            bounds.x2 += padding.left + padding.right;
            bounds.y2 += padding.top + padding.bottom;

            node.select('rect')
                .attr('x', bounds.x1)
                .attr('y', bounds.y1)
                .attr('width', bounds.x2 - bounds.x1)
                .attr('height', bounds.y2 - bounds.y1);

            d.extent = {
                left: bounds.x1 - margin.left,
                right: bounds.x2 + margin.left + margin.right,
                top: bounds.y1 - margin.top,
                bottom: bounds.y2 + margin.top + margin.bottom
            };

            d.edge = {
                left: new geo.LineSegment(bounds.x1, bounds.y1, bounds.x1, bounds.y2),
                right: new geo.LineSegment(bounds.x2, bounds.y1, bounds.x2, bounds.y2),
                top: new geo.LineSegment(bounds.x1, bounds.y1, bounds.x2, bounds.y1),
                bottom: new geo.LineSegment(bounds.x1, bounds.y2, bounds.x2, bounds.y2)
            };
        });

        graph.numTicks = 0;
        graph.preventCollisions = false;
        graph.simulation.restart();
        for (var i = 0; i < config.graph.ticksWithoutCollisions; i++) {
            graph.simulation.tick();
        }
        graph.preventCollisions = true;
        $('#graph-container').css('visibility', 'visible');
    });

    graph.legend = graph.svg.append('g')
        .attr('class', 'legend')
        .attr('x', 0)
        .attr('y', 0)
        .selectAll('.category')
        .data(Object.values(graph.categories))
        .enter().append('g')
        .attr('class', 'category')
        .call(drag_table);

    graph.legendConfig = {
        rectWidth: 12,
        rectHeight: 12,
        xOffset: -10,
        yOffset: 5,
        xOffsetText: 20,
        yOffsetText: 10,
        lineHeight: 15
    };
    graph.legendConfig.xOffsetText += graph.legendConfig.xOffset;
    graph.legendConfig.yOffsetText += graph.legendConfig.yOffset;

    graph.legend.append('rect')
        .attr('x', graph.legendConfig.xOffset)
        .attr('y', function (d, i) {
            return graph.legendConfig.yOffset + i * graph.legendConfig.lineHeight;
        })
        .attr('height', graph.legendConfig.rectHeight)
        .attr('width', graph.legendConfig.rectWidth)
        .attr('fill', function (d) {
            return graph.fillColor(d.key);
        })
        .attr('stroke', function (d) {
            return graph.strokeColor(d.key);
        })
        .on('mouseover', function (event, d) {
            highlightGroup(event, d);
        })
        .on('mouseout', function (event, d) {
            highlightGroup(null, null);
        });

    graph.legend.append('text')
        .attr('x', graph.legendConfig.xOffsetText)
        .attr('y', function (d, i) {
            return graph.legendConfig.yOffsetText + i * graph.legendConfig.lineHeight;
        })
        .text(function (d) {
            return d.typeName + (d.group ? ': ' + d.group : '');
        });

}

var maxLineChars = 26,
    wrapChars = ' /_-.'.split('');

function wrap(text) {
    if (text.length <= maxLineChars) {
        return [text];
    } else {
        for (var k = 0; k < wrapChars.length; k++) {
            var c = wrapChars[k];
            for (var i = maxLineChars; i >= 0; i--) {
                if (text.charAt(i) === c) {
                    var line = text.substring(0, i + 1);
                    return [line].concat(wrap(text.substring(i + 1)));
                }
            }
        }
        return [text.substring(0, maxLineChars)]
            .concat(wrap(text.substring(maxLineChars)));
    }
}

function preventCollisions() {
    var quadtree = d3.quadtree()
        .x(function (d) { return d['x']; })
        .y(function (d) { return d['y']; })
        .addAll(graph.simulation.nodes());

    for (var name in graph.data.nodes) {
        var obj = graph.data.nodes[name],
            ox1 = obj.x + obj.extent.left,
            ox2 = obj.x + obj.extent.right,
            oy1 = obj.y + obj.extent.top,
            oy2 = obj.y + obj.extent.bottom;

        quadtree.visit(function (quad, x1, y1, x2, y2) {
            if (!quad.length) {
                do {
                    if (quad.data && quad.data !== obj) {
                        // Check if the rectangles intersect
                        var p = quad.data,
                            px1 = p.x + p.extent.left,
                            px2 = p.x + p.extent.right,
                            py1 = p.y + p.extent.top,
                            py2 = p.y + p.extent.bottom,
                            ix = (px1 <= ox2 && ox1 <= px2 && py1 <= oy2 && oy1 <= py2);
                        if (ix) {
                            var xa1 = ox2 - px1, // shift obj left , p right
                                xa2 = px2 - ox1, // shift obj right, p left
                                ya1 = oy2 - py1, // shift obj up   , p down
                                ya2 = py2 - oy1, // shift obj down , p up
                                adj = Math.min(xa1, xa2, ya1, ya2);

                            if (adj == xa1) {
                                obj.x -= (adj / 2) + 20;
                                if (obj.x < 0) { obj.x = 0; }
                                //if (obj.x > graph.width) { obj.x = graph.width - 20;}
                                p.x += (adj / 2) + 20;
                                if (p.x > graph.width) { p.x = p.x - 20; }
                            } else if (adj == xa2) {
                                obj.x += (adj / 2) + 20;
                                p.x -= (adj / 2) + 20;
                                if (p.x < 0) { p.x = 0; }
                                //if (obj.x > graph.width) { obj.x = graph.width - 20;}
                                //if (p.x > graph.width) { p.x = graph.width - 20;}
                            } else if (adj == ya1) {
                                obj.y -= adj / 2;
                                if (obj.y < 0) { obj.y = 0; }
                                p.y += adj / 2;
                            } else if (adj == ya2) {
                                obj.y += adj / 2;
                                p.y -= adj / 2;
                                if (p.y < 0) { p.y = 0; }
                            }
                        }
                        return ix;
                    }
                } while (quad = quad.next)
            }
            return 0;
        });
    }
}

function tick() {
    graph.numTicks++;

    for (var name in graph.data.nodes) {
        var obj = graph.data.nodes[name];

        obj.positionConstraints.forEach(function (c) {
            var w = c.weight * graph.simulation.alpha();
            if (!isNaN(c.x)) {
                obj.x = (c.x * w + obj.x * (1 - w));
            }
            if (!isNaN(c.y)) {
                obj.y = (c.y * w + obj.y * (1 - w));
            }
        });
    }

    if (graph.preventCollisions) {
        preventCollisions();
    }

    graph.line
        .attr('x1', function (d) {
            return d.source.x;
        })
        .attr('y1', function (d) {
            return d.source.y;
        })
        .each(function (d) {
            if (isIE) {
                this.parentNode.insertBefore(this, this);
            }

            var x = d.target.x,
                y = d.target.y,
                line = new geo.LineSegment(d.source.x, d.source.y, x, y);

            for (var e in d.target.edge) {
                var ix = line.intersect(d.target.edge[e].offset(x, y));
                if (ix.in1 && ix.in2) {
                    x = ix.x;
                    y = ix.y;
                    break;
                }
            }

            d3.select(this)
                .attr('x2', x)
                .attr('y2', y);
        });

    graph.node
        .attr('transform', function (d) {
            return 'translate(' + d.x + ',' + d.y + ')';
        })
        .attr("cx", function (d) { return d.x; })
        .attr("cy", function (d) { return d.y; });
}

function selectObject(obj, el) {
    var node;
    if (el) {
        node = d3.select(el);
    } else {
        graph.node.each(function (d) {
            if (d === obj) {
                node = d3.select(el = this);
            }
        });
    }
    if (!node) return;

    if (node.classed('selected')) {
        deselectObject();
        return;
    }
    deselectObject(false);

    selected = {
        obj: obj,
        el: el
    };

    highlightObject(null, obj);

    node.classed('selected', true);
    $('#docs').html(createDocs(obj));
    $('#docs-container').scrollTop(0);
    resize(true);

    var $graph = $('#graph-container'),
        nodeRect = {
            left: obj.x + obj.extent.left + graph.margin.left,
            top: obj.y + obj.extent.top + graph.margin.top,
            width: obj.extent.right - obj.extent.left,
            height: obj.extent.bottom - obj.extent.top
        },
        graphRect = {
            left: $graph.scrollLeft(),
            top: $graph.scrollTop(),
            width: $graph.width(),
            height: $graph.height()
        };
    if (nodeRect.left < graphRect.left ||
        nodeRect.top < graphRect.top ||
        nodeRect.left + nodeRect.width > graphRect.left + graphRect.width ||
        nodeRect.top + nodeRect.height > graphRect.top + graphRect.height) {

        $graph.animate({
            scrollLeft: nodeRect.left + nodeRect.width / 2 - graphRect.width / 2,
            scrollTop: nodeRect.top + nodeRect.height / 2 - graphRect.height / 2
        }, 500);
    }
}

function deselectObject(doResize) {
    if (doResize || typeof doResize == 'undefined') {
        resize(false);
    }
    graph.node.classed('selected', false);
    selected = {};
    highlightObject(null, null);
}


function findLinkedNodes(d, id) {
    for (let entry in graph.links) {
        if ((graph.links[entry].source.id === d.id && graph.links[entry].target.id === id) ||
            (graph.links[entry].source.id === id && graph.links[entry].target.id === d.id) ||
            (graph.links[entry].source.id.endsWith(id) && graph.links[entry].target.id === d.id) ||
            (graph.links[entry].source.id === d.id && graph.links[entry].target.id.endsWith(id))
        ) {
            return true;
        }
    }
    return false;
}

function highlightGroup(event, obj) {
    if (obj) {
        if (obj !== highlighted) {
            graph.node.classed('inactive', function (d) {
                return (obj !== d
                    && !(d.id.endsWith(obj.key))
                    && obj.key !== d.id
                    && findLinkedNodes(d, obj.key) === false);
            });
            graph.line.classed('inactive', function (d) {
                return (true);
            });
        }
        highlighted = obj;
    } else {
        if (highlighted) {
            graph.node.classed('inactive', false);
            graph.line.classed('inactive', false);
        }
        highlighted = null;
    }
}

function highlightObject(event, obj) {
    if (obj) {
        if (obj !== highlighted) {
            graph.node.classed('inactive', function (d) {
                return (obj !== d
                    && findLinkedNodes(d, obj.id) === false);
            });
            graph.line.classed('inactive', function (d) {
                return (obj !== d.source && obj !== d.target);
            });
        }
        highlighted = obj;
    } else {
        if (highlighted) {
            graph.node.classed('inactive', false);
            graph.line.classed('inactive', false);
        }
        highlighted = null;
    }
}

var showingDocs = false,
    docsClosePadding = 8,
    desiredDocsHeight = 180;

function resize(showDocs) {
    var docsHeight = 0,
        graphHeight = 0,
        $docs = $('#docs-container'),
        $graphCtnr = $('#graph-container'),
        $graphBox = $('#graph'),
        $graphSVG = $('#graph-svg'),
        $close = $('#docs-close');

    if (typeof showDocs == 'boolean') {
        showingDocs = showDocs;
        $docs[showDocs ? 'show' : 'hide']();
    }

    if (showingDocs) {
        docsHeight = desiredDocsHeight;
        $docs.css('height', docsHeight + 'px');
    }

    let graphElement = document.getElementById('graph');

    graphHeight = window.innerHeight - docsHeight;
    $graphCtnr.css('height', graphHeight + 'px');
    $graphBox.css('height', graphHeight + 'px');
    $graphSVG.css('width', graphElement.clientWidth + 'px');
    $graphSVG.css('height', graphElement.clientHeight + 'px');

    if (graph.simulation) {
        graph.simulation.force("center", d3.forceCenter(graphElement.clientWidth / 2, graphElement.clientHeight / 2));
    }

    $close.css({
        top: graphHeight + docsClosePadding + 'px',
        right: window.innerWidth - $docs[0].clientWidth + docsClosePadding + 'px'
    });
}

function doZoom(event, obj) {
    graph.svg.attr("transform", "translate(" + event.transform.x + ", " + event.transform.y + ") scale(" + event.transform.k + ")");
}

function doSearch() {
    var item = document.getElementById('searchField').value;
    var selected = graph.svg.selectAll('.node').filter(function (d, i) {
        return d.id.toLowerCase().search(item.toLowerCase()) === -1;
    });
    selected.style('opacity', '0');
    var link = graph.svg.selectAll('.link');
    link.style('stroke-opacity', '0');
    d3.selectAll('.node').transition()
        .duration(5000)
        .style('opacity', '1');
    d3.selectAll('.link').transition().duration(5000).style('stroke-opacity', '0.6');
    return false;
}

function createCertLink(id, source) {
    let returnHTML = '<a href="';
    if (source === 'ct_logs') {
        returnHTML += '/reports/display_cert?type=ct_sha256&sha256=' + id;
    } else {
        returnHTML += '/reports/display_cert?sha256=' + id;
    }
    returnHTML += '" target="_blank">' + source + '</a>';
    return returnHTML;
}

function createDocs(obj) {
    let returnHTML = '';
    returnHTML += 'ID: ' + obj.id + '<br/>';
    returnHTML += 'Type: ' + obj.type + '<br/>';
    if (obj.type === 'certificate') {
        for (let source in obj.sources) {
            returnHTML += 'Certificate Source: ' + createCertLink(obj.id, obj.sources[source]) + '<br/>';
        }
    } else {
        if (obj.status === 'Resolves') {
            returnHTML += 'Status: <a href="/domain?search=' + obj.id + '" target="_blank">' + obj.status + '</a><br/>';
        } else {
            returnHTML += 'Status: ' + obj.status + '<br/>';
        }
    }
    let relatedNodes = '';
    for (let entry in graph.data.nodes) {
        if (findLinkedNodes(graph.data.nodes[entry], obj.id)) {
            if (graph.data.nodes[entry].type === 'certificate') {
                relatedNodes += createCertLink(graph.data.nodes[entry].id, graph.data.nodes[entry].id) + ', ';
            } else {
                relatedNodes += graph.data.nodes[entry].id + ', ';
            }
        }
    }
    returnHTML += 'Related Nodes: ' + relatedNodes.substr(0, relatedNodes.length - 2) + '<br/>';
    return returnHTML;
}

function doReload() {
    window.location.href = "/cert_graph?zone=" + document.getElementById('reloadField').value;
}

var drag_table = d3.drag().subject(this)
    .on('start', function (event, d) {
        if (d.x1) {
            d.x1 = event.x - d.xt;
            d.y1 = event.y - d.yt;
        } else {
            d.x1 = event.x;
            d.y1 = event.y;
        }
    })
    .on('drag', function (event, d) {
        d3.select(this).attr("transform", "translate(" + (event.x - d.x1) + "," + (event.y - d.y1) + ")");

        d.xt = event.x - d.x1;
        d.yt = event.y - d.y1;
    });

