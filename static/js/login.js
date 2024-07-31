async function login() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  const formData = new URLSearchParams();
  formData.append('username', username);
  formData.append('password', password);

  const response = await fetch('/api/auth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: formData.toString()
  });

  const data = await response.json();
  console.log('Login response:', data); // Debug log

  if (response.ok) {
    alert('Login successful');
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('controls').style.display = 'block';
    document.getElementById('main').style.display = 'block';
    localStorage.setItem('token', data.content.access_token);
  } else {
    alert(`Login failed: ${data.message}`);
  }
}

async function fetchData() {
  const token = localStorage.getItem('token');
  const startTime = document.getElementById('start-time').value;
  const endTime = document.getElementById('end-time').value;

  console.log('Fetching data with token:', token); // Debug log
  console.log('Fetching data with startTime:', startTime, 'and endTime:', endTime); // Debug log

  const response = await fetch(`/api/view/graph_data?start_time=${encodeURIComponent(startTime)}&end_time=${encodeURIComponent(endTime)}`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });

  const data = await response.json();
  console.log('Fetched data:', data); // Debug log

  if (response.ok && data.success) {
    const cleanedData = cleanData(data.content);
    renderGraph(cleanedData);
  } else {
    alert('Failed to fetch data');
  }
}