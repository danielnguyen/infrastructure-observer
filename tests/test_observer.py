import unittest
from infrastructure_observer.observer import Observer, FixtureProvider, projection


def c(n, project=None, **kw):
    r = {"Id": f"{n:064x}", "Name": f"/test-{n}", "Image": "sha256:synthetic", "Config": {
        "Image": "example/synthetic:v1", "Env": ["SECRET_TOKEN=private"],
        "Labels": {"SECRET=1": "hidden"}, "Cmd": ["--password=bad"]},
        "HostConfig": {"Privileged": True}, "Mounts": [{"Source": "/secret"}],
        "Labels": {"com.docker.compose.project": project} if project is not None else {},
        "State": {"Status": kw.get("status", "running"), "Health": {"Status": "healthy"}, "ExitCode": 0},
        "Ports": [{"PublicPort": 8080, "PrivatePort": 80, "Type": "tcp"}], "RestartCount": 1}
    return r

class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.ccp = c(1,"approved-project")
        self.fin = c(2,"finances")
        self.media = c(3,"media")
        self.stopped = c(4,"approved-project",status="exited")
        self.provider = FixtureProvider([self.ccp,self.fin,self.media,self.stopped], {
            self.ccp["Id"]: ["started", "token=ABC123", "Authorization: Bearer mysecret"],
            self.fin["Id"]: ["private financial transaction"]})
        self.nas = Observer("example-host-a",self.provider)
        self.uni = Observer("example-host-b",self.provider)

    def call(self, api, path, method="GET"):
        return api.handle(method, path)

    def test_all_containers_including_stopped(self):
        code, body = self.call(self.nas,"/v1/containers")
        self.assertEqual(code,200)
        self.assertEqual(len(body["containers"]),4)
        self.assertIn("exited",{i["status"] for i in body["containers"]})
    def test_inspect_field_allowlist(self):
        code, body = self.call(self.nas,"/v1/containers/"+self.ccp["Id"])
        self.assertEqual(code,200)
        raw = str(body)
        for secret in ("SECRET_TOKEN", "mysecret", "password", "/secret", "Privileged", "Cmd", "Mounts", "HostConfig"):
            self.assertNotIn(secret,raw)
    def test_project_counts(self):
        code, body = self.call(self.nas,"/v1/projects")
        self.assertEqual(code,200)
        self.assertEqual({p["name"]:p["count"] for p in body["projects"]}["approved-project"],2)
    def test_ccp_logs_allowed_and_redacted(self):
        code, body = self.call(self.nas,"/v1/projects/approved-project/logs?since_minutes=5&limit=20")
        self.assertEqual(code,200)
        self.assertIn("[REDACTED]",str(body))
        self.assertNotIn("ABC123",str(body))
        self.assertNotIn("mysecret",str(body))
    def test_other_projects_denied(self):
        for name in ("finances","media","home-devops","llm-memor"):
            self.assertEqual(self.call(self.nas,f"/v1/projects/{name}/logs?since_minutes=5&limit=20")[0],403)
    def test_second_host_denied_all_logs(self):
        self.assertEqual(self.call(self.uni,"/v1/projects/approved-project/logs?since_minutes=5&limit=20")[0],403)
    def test_missing_project_label_denies_logs(self):
        api=Observer("example-host-a",FixtureProvider([c(1)]))
        self.assertEqual(self.call(api,"/v1/projects/approved-project/logs?since_minutes=5&limit=20")[0],403)
    def test_wrong_or_ambiguous_label_denies_logs(self):
        r=c(1,"LLM-Memory")
        api=Observer("example-host-a",FixtureProvider([r]))
        self.assertEqual(self.call(api,"/v1/projects/approved-project/logs?since_minutes=5&limit=20")[0],403)
        api=Observer("example-host-a",FixtureProvider([c(1,"approved-project"),c(1,"finances")]))
        self.assertEqual(self.call(api,"/v1/projects/approved-project/logs?since_minutes=5&limit=20")[0],503)
    def test_no_mutations(self):
        for method in ("POST","DELETE","PUT","PATCH"):
            self.assertEqual(self.call(self.nas,"/v1/containers",method)[0],405)
    def test_reject_unrecognized_routes_and_traversal(self):
        for path in ("/v1/containers/../delete", "/v1/projects/approved-project/../../finances/logs", "/v1/docker.sock", "/v1/containers/%2e%2e", "//v1/containers", "/v1/projects/approved-project/logs?since_minutes=5&limit=20&limit=20"):
            self.assertNotEqual(self.call(self.nas,path)[0],200)
    def test_query_bounds(self):
        for query in ("since_minutes=0&limit=10", "since_minutes=16&limit=10", "since_minutes=5&limit=101", "since_minutes=5&limit=10&foo=bar", "since_minutes=5&limit=-1"):
            self.assertEqual(self.call(self.nas,"/v1/projects/approved-project/logs?"+query)[0],400)
    def test_no_raw_inspect(self):
        fields=projection(self.ccp,True)
        self.assertNotIn("Env",fields)
        self.assertNotIn("Labels",fields)
        self.assertNotIn("Mounts",fields)
    def test_errors_are_partial_not_healthy(self):
        class Broken(FixtureProvider):
            def list_containers(self): raise RuntimeError("SECRET failure")
        code, body = self.call(Observer("example-host-a",Broken([])),"/v1/containers")
        self.assertEqual(code,503)
        self.assertEqual(body["error"],"OBSERVATION_UNAVAILABLE")
        self.assertTrue(body["partial"])
        self.assertNotIn("SECRET",str(body))
    def test_stale_removed_container_no_inspect(self):
        self.assertEqual(self.call(self.nas,"/v1/containers/"+"f"*64)[0],404)

if __name__ == '__main__': unittest.main()
