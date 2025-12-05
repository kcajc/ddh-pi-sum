mod p1;
mod p2;

fn main() {
    let p1 = p1::P1::new(vec!["alice", "charlie", "eve"]);
    let p2 = p2::P2::new(vec![
        ("alice", 100), // Intersect
        ("bob", 999),
        ("charlie", 50), // Intersect
        ("dave", 999),
    ]);
    let msg_1 = p1.round_1();
    let msg_2 = p2.round_2(msg_1);
    let msg_3 = p1.round_3(&p2.pk, msg_2);
    p2.output(&msg_3);
}
