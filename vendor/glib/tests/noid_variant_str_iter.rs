use glib::variant::ToVariant;

/// Must also run in release mode: optimization exposed the old out-pointer UB.
#[test]
fn string_array_iteration_is_sound_from_both_ends() {
    let values = ["north", "south", "east", "west"];
    let variant = values.as_slice().to_variant();
    let mut iter = variant.array_iter_str().expect("fixture is a string array");
    assert_eq!(iter.next(), Some("north"));
    assert_eq!(iter.next_back(), Some("west"));
    assert_eq!(iter.nth(1), Some("east"));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next_back(), None);

    let mut reverse = variant.array_iter_str().expect("fixture is a string array");
    assert_eq!(reverse.nth_back(1), Some("east"));
    assert_eq!(reverse.next(), Some("north"));
    assert_eq!(reverse.next_back(), Some("south"));
    assert_eq!(reverse.next(), None);
}
