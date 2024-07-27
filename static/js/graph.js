// Function to clean data
function cleanData(data) {
  const cleanedData = { nodes: [], edges: [] };
  const nodeIds = new Set();
  const edgeSet = new Set();
  let minBytes = Infinity;
  let maxBytes = -Infinity;

  const graphs = Array.isArray(data) ? data : [data];
  graphs.forEach(graph => {
    graph.edges.forEach(edge => {
      if (edge.bytes_toserver < minBytes) minBytes = edge.bytes_toserver;
      if (edge.bytes_toserver > maxBytes) maxBytes = edge.bytes_toserver;
      if (edge.bytes_toclient < minBytes) minBytes = edge.bytes_toclient;
      if (edge.bytes_toclient > maxBytes) maxBytes = edge.bytes_toclient;
    });
  });

  const scaleBytes = bytes => 1 + ((bytes - minBytes) / (maxBytes - minBytes)) * 9;

  graphs.forEach(graph => {
    graph.nodes.forEach(node => {
      if (node.src_ip && node.dest_ip) {
        const nodeId = node.src_ip;
        if (!nodeIds.has(nodeId)) {
          nodeIds.add(nodeId);
          cleanedData.nodes.push(createNode(node, 'src_ip'));
        }
        const destNodeId = node.dest_ip;
        if (!nodeIds.has(destNodeId)) {
          nodeIds.add(destNodeId);
          cleanedData.nodes.push(createNode(node, 'dest_ip'));
        }
      }
    });

    graph.edges.forEach(edge => {
      if (edge.src_ip && edge.dest_ip) {
        const edgeKey = `${edge.src_ip}-${edge.dest_ip}`;
        if (!edgeSet.has(edgeKey)) {
          edgeSet.add(edgeKey);
          cleanedData.edges.push(createEdge(edge, scaleBytes));
        }
      }
    });
  });

  return cleanedData;
}

// Function to create a node
function createNode(node, type) {
  const ip = node[type];
  const tags = node.tags[type] || [];

  return {
    id: ip,
    name: ip,
    symbol: 'circle',
    symbolSize: 30,
    itemStyle: {
      color: tags.includes('critical') ? 'red' : tags.includes('suspicious') ? 'yellow' : 'blue'
    },
    label: {
      show: true,
      position: 'right',
      distance: 20,
      formatter: params => params.data.name,
      fontSize: 14
    }
  };
}

// Function to create an edge
function createEdge(edge, scaleBytes) {
  const isFlow = edge.event_type === 'flow';
  const color = isFlow ? 'blue' : 'red';
  const width = isFlow ? scaleBytes(edge.bytes_toclient + edge.bytes_toserver) : 5;

  return {
    source: edge.src_ip,
    target: edge.dest_ip,
    lineStyle: {
      width: width,
      curveness: 0.3,
      color: color
    },
    emphasis: {
      focus: 'adjacency',
      lineStyle: {
        width: 10
      }
    },
    edgeEffect: {
      show: true,
      period: 6,
      trailLength: 0.7,
      color: color,
      symbol: 'arrow',
      symbolSize: 5
    }
  };
}

// Function to render the graph
function renderGraph(data) {
  const chart = echarts.init(document.getElementById('main'));
  const option = {
    title: {
      text: 'Threat Graph',
      subtext: 'AIXIOR',
      top: 'top',
      left: 'center'
    },
    tooltip: {
      trigger: 'item',
      formatter: formatTooltip
    },
    legend: [{
      data: ['Category1', 'Category2']
    }],
    animationDuration: 1500,
    animationEasingUpdate: 'quinticInOut',
    series: [{
      name: 'Graph',
      type: 'graph',
      layout: 'force',
      data: data.nodes,
      links: data.edges,
      categories: [],
      roam: true,
      label: {
        position: 'right',
        distance: 20,
        formatter: '{b}',
        fontSize: 14
      },
      lineStyle: {
        curveness: 0.3
      },
      emphasis: {
        focus: 'adjacency',
        lineStyle: {
          width: 10
        }
      },
      force: {
        repulsion: 10000,
        edgeLength: [100, 200],
        gravity: 0.1,
        layoutAnimation: true,
        friction: 0.6,
      }
    }],
    dataZoom: [{
      type: 'inside',
      zoomOnMouseWheel: true,
      zoomLock: false,
      throttle: 100
    }]
  };

  chart.setOption(option);
  window.myChart = chart;
}

// Function to format tooltip content
function formatTooltip(params) {
  if (params.dataType === 'node') {
    return `
      <strong>${params.data.id}</strong><br/>
      IP: ${params.data.name || 'No info'}<br/>
      ${params.data.node_type ? `Node Type: ${params.data.node_type}<br/>` : ''}
      ${params.data.abnormal_score ? `Abnormal Score: ${params.data.abnormal_score}<br/>` : ''}
      ${params.data.cti_intelligence ? `CTI Intelligence: ${params.data.cti_intelligence}<br/>` : ''}
      ${params.data.host_event_log ? `Host Event Log: ${params.data.host_event_log}<br/>` : ''}
      ${params.data.host_info ? `Host Info: ${params.data.host_info}<br/>` : ''}
      OS: ${params.data.os || 'No info'}<br/>
      Abnormal Count: ${params.data.abnormal_count || 'No info'}
    `;
  } else {
    return `
      <strong>Edge</strong><br/>
      Source: ${params.data.source || 'No info'}<br/>
      Target: ${params.data.target || 'No info'}<br/>
      Source IP: ${params.data.src_ip || 'No info'}<br/>
      Destination IP: ${params.data.dest_ip || 'No info'}<br/>
      Source Port: ${params.data.src_port || 'No info'}<br/>
      Destination Port: ${params.data.dest_port || 'No info'}<br/>
      Signature: ${params.data.signature ? params.data.signature : 'N/A'}<br/>
      Severity: ${params.data.severity ? params.data.severity : 'N/A'}<br/>
      Bytes to Server: ${params.data.bytes_toserver || 'No info'}<br/>
      Bytes to Client: ${params.data.bytes_toclient || 'No info'}
    `;
  }
}

// Function to zoom in
function zoomIn() {
  window.zoomLevel = (window.zoomLevel || 1) * 1.1;
  myChart.dispatchAction({
    type: 'dataZoom',
    start: 100 - (100 / window.zoomLevel),
    end: 100
  });
}

// Function to zoom out
function zoomOut() {
  window.zoomLevel = (window.zoomLevel || 1) / 1.1;
  myChart.dispatchAction({
    type: 'dataZoom',
    start: 100 - (100 / window.zoomLevel),
    end: 100
  });
}

// Adjust chart size on window resize
window.addEventListener('resize', () => {
  myChart.resize();
});
