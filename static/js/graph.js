let myChart;

// Function to clean and process data
function cleanData(data) {
  console.log('Cleaning Data:', data); // Log data before processing

  const cleanedData = { nodes: [], edges: [] };
  const nodeIds = new Set();
  const edgeSet = new Set();

  // Ensure data.nodes and data.edges are arrays
  if (!Array.isArray(data.nodes)) {
    console.error('data.nodes is not an array:', data.nodes);
    return cleanedData;
  }

  if (!Array.isArray(data.edges)) {
    console.error('data.edges is not an array:', data.edges);
    return cleanedData;
  }

  data.nodes.forEach(node => {
    console.log('Processing Node:', node); // Log each node
    if (!nodeIds.has(node.id)) {
      nodeIds.add(node.id);
      cleanedData.nodes.push({
        id: node.id,
        name: node.id,
        symbol: 'circle',
        symbolSize: 30,
        itemStyle: {
          color: isInternalIP(node.id) ? 'blue' : 'red'
        },
        label: {
          show: true,
          position: 'right',
          distance: 20,
          formatter: params => params.data.name,
          fontSize: 14
        }
      });
    }
  });

  data.edges.forEach(edge => {
    console.log('Processing Edge:', edge); // Log each edge
    const edgeKey = `${edge.source}-${edge.target}`;
    if (!edgeSet.has(edgeKey)) {
      edgeSet.add(edgeKey);
      cleanedData.edges.push({
        source: edge.source,
        target: edge.target,
        lineStyle: {
          width: edge.attributes.event_type === 'flow' ? 5 : 2,
          curveness: 0.3,
          color: edge.attributes.event_type === 'flow' ? 'blue' : 'red'
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
          color: edge.attributes.event_type === 'flow' ? 'blue' : 'red',
          symbol: 'arrow',
          symbolSize: 5
        }
      });
    }
  });

  console.log('Cleaned Data:', cleanedData); // Log the cleaned data
  return cleanedData;
}

// Function to determine if an IP is internal
function isInternalIP(ip) {
  const internalRanges = [
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./
  ];

  return internalRanges.some(regex => regex.test(ip));
}

// Function to render the graph
function renderGraph(data) {
  myChart = echarts.init(document.getElementById('main'));
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
    animationDuration: 1500,
    animationEasingUpdate: 'quinticInOut',
    series: [{
      name: 'Graph',
      type: 'graph',
      layout: 'force',
      data: data.nodes,
      links: data.edges,
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
  console.log('Graph rendered with data:', data); // Log the rendered graph data
}

// Function to format tooltip content
function formatTooltip(params) {
  if (params.dataType === 'node') {
    return `<strong>${params.data.id}</strong><br/>IP: ${params.data.name || 'No info'}`;
  } else {
    return `<strong>Edge</strong><br/>Source: ${params.data.source || 'No info'}<br/>Target: ${params.data.target || 'No info'}`;
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
  if (myChart) {
    myChart.resize();
  }
});
