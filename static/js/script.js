// Initialize ECharts
const chartDom = document.getElementById('main');
const myChart = echarts.init(chartDom);
let option;
let zoomLevel = 1; // Initial zoom level

// Function to fetch data
function fetchData() {
  const startTime = document.getElementById('start-time').value;
  const endTime = document.getElementById('end-time').value;


  if (!startTime || !endTime) {
    alert("Please enter both start and end times.");
    return;
  }

  console.log('startTime: ', startTime);
  console.log('endTime: ', endTime);

  const url = new URL("http://127.0.0.1:8000/get_hourly_graphs");
  url.searchParams.append("start_time", startTime);
  url.searchParams.append("end_time", endTime);

  myChart.showLoading();

  fetch(url)
    .then(response => {
      if (!response.ok) {
        throw new Error(`Network response was not ok: ${response.statusText}`);
      }
      return response.json();
    })
    .then(data => {
      myChart.hideLoading();
      const graphData = cleanData(data);
      renderGraph(graphData);
    })
    .catch(error => {
      console.error("Error loading data:", error);
      myChart.hideLoading();
      alert("Error loading data: " + error.message);
    });
}

// Function to clean data
function cleanData(data) {
  const cleanedData = { nodes: [], edges: [] };
  const nodeIds = new Set();
  const edgeSet = new Set();
  let minCount = Infinity;
  let maxCount = -Infinity;
  let minPackets = Infinity;
  let maxPackets = -Infinity;

  const graphs = Array.isArray(data) ? data : [data];
  graphs.forEach(graph => {
    graph.edges.forEach(edge => {
      if (edge.attributes.count < minCount) minCount = edge.attributes.count;
      if (edge.attributes.count > maxCount) maxCount = edge.attributes.count;
      if (edge.attributes['flow.bytes_toclient'] < minPackets) minPackets = edge.attributes['flow.bytes_toclient'];
      if (edge.attributes['flow.bytes_toclient'] > maxPackets) maxPackets = edge.attributes['flow.bytes_toclient'];
    });
  });

  const scaleCount = count => 1 + ((count - minCount) / (maxCount - minCount)) * 9;
  const scalePackets = packets => 1 + ((packets - minPackets) / (maxPackets - minPackets)) * 9;

  graphs.forEach(graph => {
    graph.nodes.forEach(node => {
      if (node.id && node.attributes) {
        const nodeId = node.id;
        if (!nodeIds.has(nodeId)) {
          nodeIds.add(nodeId);
          cleanedData.nodes.push(createNode(node));
        }
      }
    });

    graph.edges.forEach(edge => {
      if (edge.source && edge.target && edge.attributes) {
        const edgeKey = `${edge.source}-${edge.target}`;
        if (!edgeSet.has(edgeKey)) {
          edgeSet.add(edgeKey);
          cleanedData.edges.push(createEdge(edge, scaleCount, scalePackets));
        }
      }
    });
  });

  return cleanedData;
}

// Function to create a node
function createNode(node) {
  return {
    id: node.id,
    name: `${node.attributes.ip} (${node.attributes.ip_type})`,
    ...node.attributes,
    symbol: node.attributes.symbol || 'circle',
    symbolSize: 30,
    itemStyle: {
      color: node.attributes.ip === '192.168.65.137' ? 'yellow' : (node.attributes.ip_type === 'internal' ? 'blue' : 'red')
    },
    label: {
      show: true,
      position: 'right',
      distance: 20,
      formatter: params => `${params.data.ip} (${params.data.ip_type})`,
      fontSize: 14
    }
  };
}
// Function to create an edge (continued)
function createEdge(edge, scaleCount, scalePackets) {
  const isFlow = edge.attributes.hasOwnProperty('flow.bytes_toclient');
  const color = isFlow ? 'blue' : 'red';
  const width = isFlow ? scalePackets(edge.attributes['flow.bytes_toclient']) : scaleCount(edge.attributes.count);

  return {
    source: edge.source,
    target: edge.target,
    ...edge.attributes,
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
  option = {
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
        friction: 0.6
      }
    }],
    dataZoom: [{
      type: 'inside',
      zoomOnMouseWheel: true,
      zoomLock: false,
      throttle: 100
    }]
  };

  myChart.setOption(option);
}

// Function to format tooltip content
function formatTooltip(params) {
  if (params.dataType === 'node') {
    return `
      <strong>${params.data.id}</strong><br/>
      IP: ${params.data.ip}<br/>
      IP Type: ${params.data.ip_type}<br/>
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
      Source: ${params.data.source}<br/>
      Target: ${params.data.target}<br/>
      Source IP: ${params.data.source_ip}<br/>
      Destination IP: ${params.data.dest_ip}<br/>
      Source Port: ${params.data.source_port}<br/>
      Destination Port: ${params.data.dest_port}<br/>
      Signature: ${params.data.signature ? params.data.signature : 'N/A'}<br/>
      Severity: ${params.data.severity ? params.data.severity : 'N/A'}<br/>
      Count: ${params.data.count}
    `;
  }
}

// Function to zoom in
function zoomIn() {
  zoomLevel *= 1.1;
  myChart.dispatchAction({
    type: 'dataZoom',
    start: 100 - (100 / zoomLevel),
    end: 100
  });
}

// Function to zoom out
function zoomOut() {
  zoomLevel /= 1.1;
  myChart.dispatchAction({
    type: 'dataZoom',
    start: 100 - (100 / zoomLevel),
    end: 100
  });
}

// Adjust chart size on window resize
window.addEventListener('resize', () => {
  myChart.resize();
});
